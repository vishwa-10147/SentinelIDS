import pandas as pd

DATA_PATH = "datasets/raw/train_test_network.csv"

df = pd.read_csv(DATA_PATH)

print("✅ Dataset Loaded Successfully!")
print("Shape:", df.shape)

print("\n📌 Columns:")
print(df.columns)

print("\n📌 First 5 Rows:")
print(df.head())

print("\n📌 Missing Values:")
print(df.isnull().sum().sort_values(ascending=False).head(10))
