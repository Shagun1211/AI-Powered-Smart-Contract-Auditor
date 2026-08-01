from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from parser import run_slither, parse_vulnerabilities
from llm_analyzer import analyze_with_llm
from merge_findings import merge_findings
from risk_calculator import calculate_risk_score
from pdf_generator import generate_pdf

import tempfile
import os

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)

last_audit = {}


@app.post("/audit")
async def audit_contract(file: UploadFile = File(...)):

    global last_audit

  
    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".sol",
        delete=False
    ) as tmp:

        content = await file.read()

        tmp.write(content.decode("utf-8"))

        tmp_path = tmp.name

    try:


        slither_output = run_slither(tmp_path)

        slither_findings = parse_vulnerabilities(slither_output)


        with open(tmp_path, "r") as f:
            contract_code = f.read()


        llm_data = analyze_with_llm(
            contract_code,
            slither_findings
        )


        merged_findings = merge_findings(
            slither_findings,
            llm_data["additional_vulnerabilities"]
        )

        risk_score, summary = calculate_risk_score(
            merged_findings
        )

        result = {

            "status": "success",

            "merged_findings": merged_findings,

            "risk_score": risk_score,

            "summary": summary,

            "slither_findings": slither_findings,

            "llm_findings": llm_data["additional_vulnerabilities"],

            "total_vulnerabilities": len(merged_findings)

        }

        last_audit = result

        return result

    finally:

         if os.path.exists(tmp_path):
            os.unlink(tmp_path)


@app.get("/download-report")
def download_report():

    if not last_audit:

        return {

            "error": "No audit has been performed yet."

        }

    pdf_path = generate_pdf(last_audit)

    return FileResponse(

        pdf_path,

        media_type="application/pdf",

        filename="audit_report.pdf"

    )


@app.get("/")
def root():

    return {

        "message": "Smart Contract Auditor API Running"

    }