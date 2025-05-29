from transformers_pipelines import (
    Dot_file_transformer,
    Bad_user_agent_transformer,
    has_referrer_transformer,
    Suspicious_path_transformer,
    BotLabelGenerator,
    UserAgentParser,
    User_agent_browser_cleanup,
    User_agent_os_cleanup,
    ArrayToDataFrame,
    cat_pipeline,
    Dot_pipeline,
    Bad_ua_pipeline,
    sus_path_pipeline,
    parse_user_agent_pipeline,
    has_referrer_pipeline,
    bot_pipeline,
    browser_pipeline,
    os_pipeline,
    data_featuring,
    data_extracting,
    to_encode_extracting_categories,
    transform_df_for_random_forest
)

import numpy as np
import pandas as pd
import re
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.impute import SimpleImputer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score, cross_val_predict
from sklearn.utils.validation import check_array, check_is_fitted
from user_agents import parse
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score, precision_recall_curve
from sklearn.model_selection import GridSearchCV, RandomizedSearchCV
import joblib
import os
import psycopg2  # PostgreSQL connection
import time
from clean_logs import log_data_to_df,log_list_to_df
from kafka import KafkaConsumer

# Settings
TOPIC = 'nginx-logs'
MAX_MESSAGES = 100
MAX_WAIT_SECONDS = 120

# Load your base data and model
base_log_df = log_data_to_df('final_access.log')
Random_forest_model = joblib.load('bot_detection_model.pkl')

# PostgreSQL connection setup
conn = psycopg2.connect(
    host="my-postgres",  # Docker service name of your Postgres container
    database="mydb",
    user="admin",
    password="secret"
)
cursor = conn.cursor()

insert_query = """
INSERT INTO kafka_logs (
    ip, access_date, access_time, request_method, path, protocol,
    response_code, referrer, user_agent, model_prediction, heuristic_label
) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
"""

consumer = KafkaConsumer(
    TOPIC,
    bootstrap_servers='kafka:9092',
    group_id='batch-processor',
    auto_offset_reset='latest',
    enable_auto_commit=True,
    value_deserializer=lambda m: m.decode('utf-8')
)

print(f"Listening to topic '{TOPIC}'...")

buffer = []
start_time = time.time()

for message in consumer:
    buffer.append(message.value)

    time_elapsed = time.time() - start_time
    if time_elapsed % 10 == 0:
        print(time_elapsed)
    if len(buffer) > 0 and (len(buffer) >= MAX_MESSAGES or time_elapsed >= MAX_WAIT_SECONDS):
        print(f"\n>>> Triggering batch processing ({len(buffer)} logs, {time_elapsed:.2f}s elapsed)")

        # Convert logs to DataFrame
        sample_log_df = log_list_to_df(buffer)

        # Transform features for the model
        transformed_log_df, transformed_log_df_labels = transform_df_for_random_forest(base_log_df, sample_log_df)

        # Predict
        predictions = Random_forest_model.predict(transformed_log_df)

        # Build result DataFrame with all needed columns
        result_df = pd.DataFrame({
            "ip": sample_log_df["IP"],
            "access_date": sample_log_df['Date'],
            "access_time": sample_log_df['Time'],
            "request_method": sample_log_df["Request_method"],
            "path": sample_log_df["Path"],
            "protocol": sample_log_df["Protocol"],
            "response_code": sample_log_df["Response_code"].astype(int),
            "referrer": sample_log_df["Referrer"],
            "user_agent": sample_log_df["User_Agent"],
            "model_prediction": ["Bot" if p == 1 else "Human" for p in predictions],
            "heuristic_label": ["Bot" if y == 1 else "Human" for y in transformed_log_df_labels]
        })

        # Insert each row into PostgreSQL
        for _, row in result_df.iterrows():
            cursor.execute(insert_query, (
                row['ip'],
                row['access_date'],
                row['access_time'],
                row['request_method'],
                row['path'],
                row['protocol'],
                row['response_code'],
                row['referrer'] if pd.notna(row['referrer']) else None,
                row['user_agent'],
                row['model_prediction'],
                row['heuristic_label']
            ))

        conn.commit()

        print(f"Inserted {len(result_df)} rows into PostgreSQL.")

        # Optionally, save to CSV (your existing code)
        log_filename = "predicted_logs.csv"
        file_exists = os.path.isfile(log_filename)
        result_df.to_csv(log_filename, mode='a', header=not file_exists, index=False)

        print(result_df)

        # Reset buffer and timer
        buffer.clear()
        start_time = time.time()
