import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report
import joblib

# Завантажуємо дані для NSL-KDD
nsl_kdd_train = pd.read_csv(r'D:\TailTrace\KDD DataBase\KDDTrain+.csv')
nsl_kdd_test = pd.read_csv(r'D:\TailTrace\KDD DataBase\KDDTest+.csv')
unsw_train = pd.read_csv(r'D:\TailTrace\UNSW DataBase\UNSW_NB15_training-set.csv') # Замість шляху до файлу, використовуйте ваш локальний шлях
unsw_test = pd.read_csv(r'D:\TailTrace\UNSW DataBase\UNSW_NB15_testing-set.csv')

# Обробка даних для NSL-KDD
nsl_kdd_features = nsl_kdd_train.drop('class', axis=1)
nsl_kdd_labels = nsl_kdd_train['class']
nsl_kdd_test_features = nsl_kdd_test.drop('class', axis=1)
nsl_kdd_test_labels = nsl_kdd_test['class']

# Стандартизуємо дані
scaler = StandardScaler()
nsl_kdd_features_scaled = scaler.fit_transform(nsl_kdd_features)
nsl_kdd_test_features_scaled = scaler.transform(nsl_kdd_test_features)

# Навчаємо модель для NSL-KDD
nsl_kdd_model = RandomForestClassifier(n_estimators=100)
nsl_kdd_model.fit(nsl_kdd_features_scaled, nsl_kdd_labels)

# Оцінка моделі для NSL-KDD
nsl_kdd_predictions = nsl_kdd_model.predict(nsl_kdd_test_features_scaled)
print("NSL-KDD Classification Report:")
print(classification_report(nsl_kdd_test_labels, nsl_kdd_predictions))

# Зберігаємо модель
joblib.dump(nsl_kdd_model, 'nsl_kdd_model.pkl')

# Обробка даних для UNSW-NB15
unsw_features = unsw_train.drop('Category', axis=1)
unsw_labels = unsw_train['Category']
unsw_test_features = unsw_test.drop('Category', axis=1)
unsw_test_labels = unsw_test['Category']

# Стандартизуємо дані
unsw_features_scaled = scaler.fit_transform(unsw_features)
unsw_test_features_scaled = scaler.transform(unsw_test_features)

# Навчаємо модель для UNSW-NB15
unsw_model = RandomForestClassifier(n_estimators=100)
unsw_model.fit(unsw_features_scaled, unsw_labels)

# Оцінка моделі для UNSW-NB15
unsw_predictions = unsw_model.predict(unsw_test_features_scaled)
print("UNSW-NB15 Classification Report:")
print(classification_report(unsw_test_labels, unsw_predictions))

# Зберігаємо модель
joblib.dump(unsw_model, 'unsw_nb15_model.pkl')
