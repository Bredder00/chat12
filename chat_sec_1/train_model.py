import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
import joblib

# Загрузка данных
data = pd.read_csv('training_data.csv')

# Препроцессинг данных
X = data['message']
y = data['attack_type']
vectorizer = TfidfVectorizer()
X = vectorizer.fit_transform(X)

# Разделение данных на обучающую и тестовую выборки
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Обучение модели
model = RandomForestClassifier()
model.fit(X_train, y_train)

# Сохранение модели и векторизатора
joblib.dump(model, 'hack_detection_model.pkl')
joblib.dump(vectorizer, 'vectorizer.pkl')