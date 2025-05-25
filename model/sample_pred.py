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
from sklearn.model_selection import train_test_split, cross_val_score,cross_val_predict
from sklearn.utils.validation import check_array,check_is_fitted
from user_agents import parse
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix,precision_score,recall_score,f1_score,precision_recall_curve,precision_recall_curve
from sklearn.model_selection import GridSearchCV,RandomizedSearchCV
import joblib
import sklearn._config
from clean_logs import log_list_to_df,log_data_to_df
import pandas as pd
import joblib 

log_lines = [
    '192.168.1.10 - - [25/May/2025:14:05:32 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
    '203.0.113.45 - - [25/May/2025:14:05:34 +0000] "GET /.git/config HTTP/1.1" 403 512 "-" "python-requests/2.25.1"',
    '198.51.100.22 - - [25/May/2025:14:05:37 +0000] "GET /admin HTTP/1.1" 401 256 "-" "sqlmap/1.4.12"',
    '192.0.2.101 - - [25/May/2025:14:06:02 +0000] "POST /login HTTP/1.1" 200 890 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"',
    '203.0.113.99 - - [25/May/2025:14:06:10 +0000] "GET /search.php?q=../../etc/passwd HTTP/1.1" 400 300 "-" "curl/7.64.1"',
    '10.0.0.5 - - [25/May/2025:14:06:15 +0000] "GET /images/logo.png HTTP/1.1" 200 2048 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64)"',
    '192.168.1.15 - - [25/May/2025:14:06:20 +0000] "GET /wp-login.php HTTP/1.1" 404 123 "-" "Mozilla/5.0 (Windows NT 6.1; WOW64)"',
    '198.51.100.55 - - [25/May/2025:14:06:45 +0000] "GET /scripts/setup.php?cmd=whoami HTTP/1.1" 403 0 "-" "nikto/2.1.6 (Evasions)"',
    '172.16.0.20 - - [25/May/2025:14:07:01 +0000] "GET /contact HTTP/1.1" 200 640 "-" "Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3)"',
    '203.0.113.77 - - [25/May/2025:14:07:10 +0000] "GET /.env HTTP/1.1" 403 230 "-" "Mozilla/5.0 zgrab/0.x"',
    '10.0.0.10 - - [25/May/2025:14:07:30 +0000] "GET /dashboard HTTP/1.1" 200 3000 "-" "Mozilla/5.0 (Linux; Android 10)"',
    '192.0.2.200 - - [25/May/2025:14:07:59 +0000] "GET /cgi-bin/test-cgi HTTP/1.1" 500 105 "-" "Wget/1.20.3 (linux-gnu)"',
    '192.168.1.100 - - [25/May/2025:14:08:12 +0000] "POST /api/v1/users HTTP/1.1" 201 980 "-" "Mozilla/5.0 (Windows NT 10.0; rv:89.0)"',
    '203.0.113.15 - - [25/May/2025:14:08:30 +0000] "GET /?s=<script>alert(1)</script> HTTP/1.1" 200 450 "-" "Mozilla/5.0 (X11; Kali Linux)"',
    '198.51.100.1 - - [25/May/2025:14:08:45 +0000] "GET /phpinfo.php HTTP/1.1" 200 1500 "-" "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"',
]

base_df = log_data_to_df('final_access.log')
log_df = log_list_to_df(log_lines)

X,Y = transform_df_for_random_forest(base_df,log_df)

model = joblib.load('bot_detection_model.pkl')
predictions = model.predict(X)

print("Predictions:", predictions)
print("Columns used:", len(X.columns.tolist()))
print("True Labels (if any):", Y.tolist())
