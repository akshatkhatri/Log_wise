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

from clean_logs import log_data_to_df,log_list_to_df

class Dot_file_transformer(BaseEstimator, TransformerMixin):
    def fit(self, X, y=None):
        if isinstance(X, pd.DataFrame):
            self.feature_names_in_ = X.columns.tolist()
        else:
            self.feature_names_in_ = []
        return self

    def transform(self, X):
        if not isinstance(X, pd.DataFrame):
            X = pd.DataFrame(X, columns=['Path'])

        # Ensure 'Path' is string and fill NaNs
        path_series = X['Path'].fillna('').astype(str)

        # Apply regex to detect dotfiles
        dotfile_flag = path_series.apply(lambda p: 1 if re.search(r'/\.[^/]+', p) else 0)

        return pd.DataFrame({'dotfile_access': dotfile_flag}, index=X.index)

    def get_feature_names_out(self, input_features=None):
        return np.array(['dotfile_access'])


class Bad_user_agent_transformer(BaseEstimator, TransformerMixin):
    def __init__(self,user_agent_col = 'User_Agent'):
        self.user_agent_col = user_agent_col
        
    def fit(self, X, y=None):
        if isinstance(X, pd.DataFrame):
            self.feature_names_in_ = X.columns.tolist()
        else:
            self.feature_names_in_ = []
        return self

    def transform(self, X):
        if not isinstance(X, pd.DataFrame):
            X = pd.DataFrame(X, columns=[self.user_agent_col])

        bad_ua_flag = X[self.user_agent_col].fillna('').str.lower().str.contains(
            r"(?:bot|curl|scraper|wget|httpclient|requests|spider|crawler|expanse|censys|modat)"
        ).astype(int)

        return pd.DataFrame({'bad_user_agent': bad_ua_flag}, index=X.index)

    def get_feature_names_out(self, input_features=None):
        return np.array(['bad_user_agent'])


class has_referrer_transformer(BaseEstimator, TransformerMixin):
    def fit(self, X, y=None):
        if isinstance(X, pd.DataFrame):
            self.feature_names_in_ = X.columns.tolist()
        else:
            self.feature_names_in_ = []
        return self

    def transform(self, X):
        if not isinstance(X, pd.DataFrame):
            X = pd.DataFrame(X, columns=['Referrer'])

        has_ref = X['Referrer'].fillna('-').apply(lambda r: 0 if r == '-' else 1)
        return pd.DataFrame({'has_referrer': has_ref}, index=X.index)

    def get_feature_names_out(self, input_features=None):
        return np.array(['has_referrer'])


class Suspicious_path_transformer(BaseEstimator, TransformerMixin):
    def fit(self, X, y=None):
        if isinstance(X, pd.DataFrame):
            self.feature_names_in_ = X.columns.tolist()
        else:
            self.feature_names_in_ = []
        return self

    def transform(self, X):
        if not isinstance(X, pd.DataFrame):
            X = pd.DataFrame(X, columns=['Path'])

        suspicious_keywords = ['wp-admin', 'phpmyadmin', 'config', 'admin', 'setup',
                               'shell', 'login', 'cmd', 'api', 'backup']

        suspicious = X['Path'].fillna('').str.lower().apply(
            lambda path: int(any(keyword in path for keyword in suspicious_keywords))
        )

        return pd.DataFrame({'suspicious_path': suspicious}, index=X.index)

    def get_feature_names_out(self, input_features=None):
        return np.array(['suspicious_path'])


class BotLabelGenerator(BaseEstimator, TransformerMixin):
    def __init__(self,
                 dotfile_col='dotfile_access',
                 bad_ua_col='bad_user_agent',
                 suspicious_path_col='suspicious_path',
                 output_col='is_bot'):
        self.dotfile_col = dotfile_col
        self.bad_ua_col = bad_ua_col
        self.suspicious_path_col = suspicious_path_col
        self.output_col = output_col

    def fit(self, X, y=None):
        if isinstance(X, pd.DataFrame):
            self.feature_names_in_ = X.columns.tolist()
        else:
            self.feature_names_in_ = []
        return self

    def transform(self, X):
        if not isinstance(X, pd.DataFrame):
            raise ValueError("Input must be a pandas DataFrame.")

        try:
            # Convert columns to boolean type first, before filling NA
            dotfile = X[self.dotfile_col]
            if dotfile.dtype == object:
                dotfile = dotfile.astype('bool')
            dotfile = dotfile.fillna(False)

            bad_ua = X[self.bad_ua_col]
            if bad_ua.dtype == object:
                bad_ua = bad_ua.astype('bool')
            bad_ua = bad_ua.fillna(False)

            suspicious = X[self.suspicious_path_col]
            if suspicious.dtype == object:
                suspicious = suspicious.astype('bool')
            suspicious = suspicious.fillna(False)

            # Combine conditions
            result = (dotfile | bad_ua | suspicious).astype(int)

        except KeyError as e:
            raise KeyError(f"Missing expected column in input DataFrame: {e}")

        return pd.DataFrame({self.output_col: result}, index=X.index)


    def get_feature_names_out(self, input_features=None):
        return np.array([self.output_col])
    
    
class UserAgentParser(BaseEstimator, TransformerMixin):
    def fit(self, X, y=None):
        if not isinstance(X, pd.DataFrame):
            X = pd.DataFrame(X, columns=['User_Agent'])
        self.feature_names_in_ = X.columns.tolist()
        return self

    def transform(self, X):
        if not isinstance(X, pd.DataFrame):
            X = pd.DataFrame(X, columns=self.feature_names_in_)

        def parse_ua(ua):
            if pd.isna(ua):
                return pd.Series({
                    'ua_browser': 'no browser',
                    'ua_os': 'no OS',
                    'ua_is_mobile': 0,
                    'ua_is_pc': 0
                })
            parsed = parse(ua)
            return pd.Series({
                'ua_browser': parsed.browser.family,
                'ua_os': parsed.os.family,
                'ua_is_mobile': int(parsed.is_mobile),
                'ua_is_pc': int(parsed.is_pc),
            })

        ua_features = X.iloc[:, 0].apply(parse_ua)
        return ua_features

    def get_feature_names_out(self, input_features=None):
        return np.array(['ua_browser', 'ua_os', 'ua_is_mobile', 'ua_is_pc'])


class User_agent_browser_cleanup(BaseEstimator, TransformerMixin):
    def __init__(self, user_agent_browser='ua_browser'):
        self.user_agent_browser = user_agent_browser

    def fit(self, X, y=None):
        if not isinstance(X, pd.DataFrame):
            X = pd.DataFrame(X, columns=[self.user_agent_browser])
        self.feature_names_in_ = X.columns.tolist()
        return self

    def transform(self, X):
        if not isinstance(X, pd.DataFrame):
            X = pd.DataFrame(X, columns=self.feature_names_in_)

        col = X.columns[0]
        top_browsers = ['Chrome', 'Firefox', 'Edge', 'Chrome Mobile', 'Opera', 'no browser']
        X = X.copy()
        X[col] = X[col].apply(lambda x: x if x in top_browsers else 'Other')
        return X[[col]]

    def get_feature_names_out(self, input_features=None):
        return np.array([self.feature_names_in_[0]])


class User_agent_os_cleanup(BaseEstimator, TransformerMixin):
    def __init__(self, user_agent_os='ua_os'):
        self.user_agent_os = user_agent_os

    def fit(self, X, y=None):
        if not isinstance(X, pd.DataFrame):
            X = pd.DataFrame(X, columns=[self.user_agent_os])
        self.feature_names_in_ = X.columns.tolist()
        return self

    def transform(self, X):
        if not isinstance(X, pd.DataFrame):
            X = pd.DataFrame(X, columns=self.feature_names_in_)

        col = X.columns[0]
        top_os = ['Windows', 'iOS', 'Ubuntu', 'Linux', 'Mac OS X', 'Android', 'no OS']
        X = X.copy()
        X[col] = X[col].apply(lambda x: x if x in top_os else 'Other')
        return X[[col]]

    def get_feature_names_out(self, input_features=None):
        return np.array([self.feature_names_in_[0]])


class ArrayToDataFrame(BaseEstimator, TransformerMixin):
    def __init__(self, column_names=None):
        self.column_names = column_names

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        import pandas as pd
        return pd.DataFrame(X, columns=self.column_names)

    def get_feature_names_out(self, input_features=None):
        if self.column_names is not None:
            return np.array(self.column_names)
        else:
            # fallback if no column names were given
            if input_features is not None:
                return np.array(input_features)
            else:
                return np.array([])


'''
Below are the Neccesary Pipelines
'''

cat_pipeline = Pipeline([
    ('impute',SimpleImputer(strategy = 'most_frequent')),
    ('encoder',OneHotEncoder(handle_unknown='ignore'))
])

Dot_pipeline = Pipeline([
    ('impute',SimpleImputer(strategy = 'most_frequent')),
    ('dot_transform',Dot_file_transformer())
])

Bad_ua_pipeline = Pipeline([
    ('impute',SimpleImputer(missing_values='-',strategy='constant',fill_value = np.nan)),
    ('bad_agent',Bad_user_agent_transformer())
])

sus_path_pipeline = Pipeline([
    ('impute',SimpleImputer(strategy='most_frequent')),
    ('sus_path',Suspicious_path_transformer())
])

parse_user_agent_pipeline = Pipeline([
    ('impute',SimpleImputer(missing_values='-',strategy='constant',fill_value = np.nan)),
    ('parse_ua',UserAgentParser())
])

has_referrer_pipeline = Pipeline([
    ('check_referrer',has_referrer_transformer())
])


# Below Pipelines will only be applied when above pipelines are completed
def bot_pipeline(dot_path,user_agent_path,sus_path):
    return Pipeline([
        ('label_bot',BotLabelGenerator(dot_path,user_agent_path,sus_path))
    ])
def browser_pipeline(browser_path):
    return Pipeline([
        ('clean_browser',User_agent_browser_cleanup(browser_path)),
        ('encode',OneHotEncoder(sparse_output=False,handle_unknown='ignore'))
    ])

def os_pipeline(user_os_path):
    return Pipeline([
        ('clean_os',User_agent_os_cleanup(user_os_path)),
        ('encode',OneHotEncoder(sparse_output=False,handle_unknown='ignore'))
    ])


to_encode_extracting_categories = ['clean_browser__ua_browser','clean_os__ua_os']
data_featuring = ColumnTransformer([
    ('dot',Dot_pipeline,['Path']),
    ('bad_agent',Bad_ua_pipeline,['User_Agent']),
    ('sus_path',sus_path_pipeline,['Path']),
    ('parse_agent',parse_user_agent_pipeline,['User_Agent']),
    ('referrer_check',has_referrer_pipeline,['Referrer']),
    # ('encode',cat_pipeline,to_encode_featuring_categories)
])

data_extracting = ColumnTransformer([
    ('label',bot_pipeline('dot__dotfile_access','bad_agent__bad_user_agent','sus_path__suspicious_path'),['dot__dotfile_access','bad_agent__bad_user_agent','sus_path__suspicious_path']),
    ('clean_browser',browser_pipeline('parse_agent__ua_browser'),['parse_agent__ua_browser']),
    ('clean_os',os_pipeline('parse_agent__ua_os'),['parse_agent__ua_os']),
],remainder='passthrough')

# Converts any standard DF converted fron nginx logs into transformed DF with train_set and train_set_labels ready to be used by random forest regressor for predictions
def transform_df_for_random_forest(base_set , df_path):
    
    data_featuring.fit(base_set)  # Or whatever your base DataFrame is
    featuring_columns = data_featuring.get_feature_names_out()
    data_featuring.get_feature_names_out()

    to_df = ArrayToDataFrame(column_names=featuring_columns)

    full_pipeline = Pipeline([
        ('featuring', data_featuring),
        ('to_df', to_df),
        ('extracting', data_extracting),
    ])

    full_pipeline.fit(base_set)
    log_df_path = full_pipeline.transform(df_path)
    log_df_path_df = pd.DataFrame(log_df_path,columns = full_pipeline.get_feature_names_out(), index = df_path.index)
    # print(full_pipeline.get_feature_names_out())
    final_log_train_set = log_df_path_df.drop('label__is_bot',axis = 1).apply(pd.to_numeric)
    final_log_train_labels = log_df_path_df['label__is_bot'].astype(int)
    return final_log_train_set,final_log_train_labels
