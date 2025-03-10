from fastapi import FastAPI, Request, Form,File, UploadFile, HTTPException
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import google.generativeai as genai
import os
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import PyPDF2

# Application ---------------------------------
app = FastAPI()
templates = Jinja2Templates(directory="templates")  # Load templates


# Set up the Google API Key--------------------
os.environ["GOOGLE_API_KEY"] = "your api here"
genai.configure(api_key=os.environ["GOOGLE_API_KEY"])
# Initialize the Gemini model
# model = genai.GenerativeModel("models/gemini-1.5-pro")
model = genai.GenerativeModel("gemini-1.5-flash")

# Enable CORS for frontend integration---------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Define input model
class URLInput(BaseModel):
    url: str


# functions
def predict_fake_or_real_email_content(text):
    prompt = f"""
    You are an expert in identifying scam messages in text, email etc. Analyze the given text and classify it as:

    - **Real/Legitimate** (Authentic, safe message)
    - **Scam/Fake** (Phishing, fraud, or suspicious message)

    **for the following Text:**
    {text}

    **Return a clear message indicating whether this content is real or a scam. 
    If it is a scam, mention why it seems fraudulent. If it is real, state that it is legitimate.**

    **Only return the classification message and nothing else.**
    Note: Don't return empty or null, you only need to return message for the input text
    """

    response = model.generate_content(prompt)
    return response.text.strip() if response else "Classification failed."


def url_detection(url):
    prompt = f"""
    You are an advanced AI model specializing in URL security classification. Analyze the given URL and classify it as one of the following categories:

    1. Benign**: Safe, trusted, and non-malicious websites such as google.com, wikipedia.org, amazon.com.
    2. Phishing**: Fraudulent websites designed to steal personal information. Indicators include misspelled domains (e.g., paypa1.com instead of paypal.com), unusual subdomains, and misleading content.
    3. Malware**: URLs that distribute viruses, ransomware, or malicious software. Often includes automatic downloads or redirects to infected pages.
    4. Defacement**: Hacked or defaced websites that display unauthorized content, usually altered by attackers.

    **Example URLs and Classifications:**
    - **Benign**: "https://www.microsoft.com/"
    - **Phishing**: "http://secure-login.paypa1.com/"
    - **Malware**: "http://free-download-software.xyz/"
    - **Defacement**: "http://hacked-website.com/"

    **Input URL:** {url}

    **Output Format:**  
    - Return only a string class name
    - Example output for a phishing site:  

    Analyze the URL and return the correct classification (Only name in lowercase such as benign etc.
    Note: Don't return empty or null, at any cost return the corrected class
    """

    response = model.generate_content(prompt)
    return response.text if response else "Detection failed."


# Endpoint to classify URL-------------------------------
@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


# API endpoint for scam detection (File Upload Only)
@app.post("/scam/")
async def detect_scam(file: UploadFile = File(...), request: Request = None):
    extracted_text = ""

    # Process uploaded file
    if file.filename.endswith('.pdf'):
        pdf_reader = PyPDF2.PdfReader(file.file)
        extracted_text = " ".join([page.extract_text() for page in pdf_reader.pages if page.extract_text()])
    elif file.filename.endswith('.txt'):
        extracted_text = (await file.read()).decode("utf-8")
    else:
        return templates.TemplateResponse("index.html", {"request": request, "message": "Invalid file type. Please upload a PDF or TXT file."})

    # Ensure there is text to process
    if not extracted_text.strip():
        return templates.TemplateResponse("index.html", {"request": request, "message": "File is empty or text could not be extracted."})

    # Get prediction
    message = predict_fake_or_real_email_content(extracted_text)
    return templates.TemplateResponse("index.html", {"request": request, "message": message})



@app.post("/predict", response_class=HTMLResponse)
async def predict_url(request: Request, url: str = Form(...)):
    try:
        url = url.strip()

        if not url.startswith(("http://", "https://")):
            return templates.TemplateResponse("index.html", {
                "request": request,
                "message": "Invalid URL format.",
                "input_url": url
            })

        classification = url_detection(url)

        return templates.TemplateResponse("index.html", {
            "request": request,
            "input_url": url,
            "predicted_class": classification
        })

    except Exception as e:
        return templates.TemplateResponse("index.html", {
            "request": request,
            "message": f"Error: {str(e)}"
        })
