from fpdf import FPDF
from datetime import datetime

def generate_pdf_report(report):

    pdf = FPDF()
    pdf.add_page()

    pdf.set_font("Arial", size=12)

    for key, value in report.items():

        pdf.cell(200, 10, f"{key}: {value}", ln=True)

    filename = datetime.now().strftime("reports/report_%Y%m%d_%H%M%S.pdf")

    pdf.output(filename)

    return filename