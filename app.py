import streamlit as st
import pandas as pd
import joblib

model = joblib.load("best_phishing_model.pkl")

st.set_page_config(page_title="Phishing Website Predictor", layout="centered")

st.title("Phishing Website Predictor")
st.write("Adjust the website characteristics below to estimate phishing risk.")

having_IP_Address = st.selectbox(
    "Uses IP address instead of a domain?",
    [-1, 1],
    format_func=lambda x: "No" if x == -1 else "Yes"
)

URL_Length = st.selectbox(
    "URL Length",
    [-1, 0, 1],
    format_func=lambda x: {-1: "Suspicious", 0: "Neutral", 1: "Legitimate"}[x]
)

having_At_Symbol = st.selectbox(
    "Contains @ symbol?",
    [-1, 1],
    format_func=lambda x: "No" if x == -1 else "Yes"
)

Prefix_Suffix = st.selectbox(
    "Contains hyphen (-) in domain?",
    [-1, 1],
    format_func=lambda x: "No" if x == -1 else "Yes"
)

having_Sub_Domain = st.selectbox(
    "Subdomain level",
    [-1, 0, 1],
    format_func=lambda x: {-1: "Many / suspicious", 0: "Moderate", 1: "Low / normal"}[x]
)

SSLfinal_State = st.selectbox(
    "HTTPS / SSL state",
    [-1, 0, 1],
    format_func=lambda x: {-1: "Poor", 0: "Neutral", 1: "Secure"}[x]
)

age_of_domain = st.selectbox(
    "Domain age",
    [-1, 1],
    format_func=lambda x: "New / young" if x == -1 else "Older / established"
)

Redirect = st.selectbox(
    "Redirect behaviour",
    [0, 1],
    format_func=lambda x: "No suspicious redirect" if x == 0 else "Suspicious redirect"
)

input_df = pd.DataFrame([[
    having_IP_Address,
    URL_Length,
    having_At_Symbol,
    Prefix_Suffix,
    having_Sub_Domain,
    SSLfinal_State,
    age_of_domain,
    Redirect
]], columns=[
    "having_IP_Address",
    "URL_Length",
    "having_At_Symbol",
    "Prefix_Suffix",
    "having_Sub_Domain",
    "SSLfinal_State",
    "age_of_domain",
    "Redirect"
])

if st.button("Predict"):
    prediction = model.predict(input_df)[0]

    probs = None
    phishing_prob = None

    if hasattr(model, "predict_proba"):
        probs = model.predict_proba(input_df)[0]
        classes = list(model.classes_)

        # IMPORTANT:
        # Change this after verifying which label means phishing in your dataset.
        phishing_label = -1

        phishing_index = classes.index(phishing_label)
        phishing_prob = probs[phishing_index]

    # IMPORTANT:
    # Change this too if your dataset uses 1 for phishing instead.
    if prediction == -1:
        st.error("Prediction: Phishing")
    else:
        st.success("Prediction: Legitimate")

    if phishing_prob is not None:
        st.write(f"Phishing probability: {phishing_prob:.2%}")

        if prediction == -1:
            st.write(f"Confidence in this prediction: {phishing_prob:.2%}")
        else:
            st.write(f"Confidence in this prediction: {(1 - phishing_prob):.2%}")