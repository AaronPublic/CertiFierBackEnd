from io import BytesIO
from datetime import date, datetime
from urllib.parse import urlparse

from django.core.files.base import ContentFile
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import landscape
import requests
from PIL import Image


def _cloudinary_png_url(url):
    """Force Cloudinary image delivery as PNG for ReportLab compatibility."""
    if not isinstance(url, str):
        return url
    if 'res.cloudinary.com' not in url or '/image/upload/' not in url:
        return url
    if '/image/upload/f_png/' in url:
        return url
    return url.replace('/image/upload/', '/image/upload/f_png/', 1)


def _clamp_pct(value, default=50.0):
    try:
        pct = float(value)
    except (TypeError, ValueError):
        pct = float(default)
    return max(0.0, min(100.0, pct))


def _parse_font_size(value, default=24):
    try:
        size = float(value)
    except (TypeError, ValueError):
        size = float(default)
    return max(8.0, min(200.0, size))


def _parse_color(value):
    if isinstance(value, str) and value.strip():
        try:
            return colors.HexColor(value.strip())
        except ValueError:
            return colors.black
    return colors.black


def _certificate_field_value(cert, key):
    date_value = cert.date_issued
    if isinstance(date_value, datetime):
        formatted_date = date_value.date().isoformat()
    elif isinstance(date_value, date):
        formatted_date = date_value.isoformat()
    elif date_value is None:
        formatted_date = ''
    else:
        formatted_date = str(date_value)

    mapping = {
        'full_name': cert.full_name,
        'course': cert.course,
        'issued_by': cert.issued_by,
        'date_issued': formatted_date,
        'title': cert.title,
        'certificate_id': cert.certificate_id,
    }
    return str(mapping.get(key, ''))


def _draw_default_layout(pdf, cert):
    pdf.setFont('Helvetica', 14)
    pdf.setFillColor(colors.black)
    pdf.drawString(100, 750, f"Certificate ID: {cert.certificate_id}")
    pdf.drawString(100, 720, f"Name: {cert.full_name}")
    pdf.drawString(100, 690, f"Course: {cert.course}")
    pdf.drawString(100, 660, f"Issued By: {cert.issued_by}")
    pdf.drawString(100, 630, f"Date: {cert.date_issued}")


def _load_background_reader(template):
    if not (template and getattr(template, 'background', None)):
        return None, None, None

    background_file = template.background
    has_any_ref = any([
        bool(getattr(background_file, 'name', None)),
        bool(getattr(background_file, 'public_id', None)),
        bool(getattr(background_file, 'url', None)),
    ])
    if not has_any_ref:
        return None, None, None

    try:
        reader = None

        # Local/dev storages usually expose a filesystem path.
        image_path = getattr(background_file, 'path', None)
        if image_path:
            reader = ImageReader(image_path)

        # Cloud storages (e.g., Cloudinary) may only expose a remote URL.
        if reader is None:
            background_url = getattr(background_file, 'url', '')
            if background_url and background_url.startswith('//'):
                background_url = f"https:{background_url}"

            background_url = _cloudinary_png_url(background_url)

            parsed_url = urlparse(background_url) if background_url else None
            if background_url and parsed_url and parsed_url.scheme in {'http', 'https'}:
                try:
                    response = requests.get(background_url, timeout=15)
                    response.raise_for_status()
                    image = Image.open(BytesIO(response.content)).convert('RGB')
                    reader = ImageReader(image)
                except requests.RequestException as req_err:
                    print(f"BACKGROUND FETCH ERROR: {req_err}")
                    # Fall through to next method

        # Storage backends can also provide a file-like object.
        if reader is None:
            try:
                with background_file.open('rb') as image_fp:
                    image = Image.open(BytesIO(image_fp.read())).convert('RGB')
                    reader = ImageReader(image)
            except Exception as file_err:
                print(f"BACKGROUND OPEN ERROR: {file_err}")

        if reader is None:
            return None, None, None

        width, height = reader.getSize()

        return reader, width, height

    except Exception as e:
        print(f"BACKGROUND LOAD ERROR: {e}")
        return None, None, None

def build_certificate_pdf_bytes(cert):
    try:
        template = cert.template
        markers = []
        background_reader = None
        page_width, page_height = letter

        bg_reader, bg_width, bg_height = _load_background_reader(template)
        if bg_reader is not None and bg_width and bg_height:
            background_reader = bg_reader
            if bg_width > bg_height:
                page_width, page_height = landscape((bg_width, bg_height))
            else:
                page_width, page_height = bg_width, bg_height
        else:
            page_width, page_height = letter

        if template and isinstance(template.placeholders, dict):
            raw_markers = template.placeholders.get('markers', [])
            if isinstance(raw_markers, list):
                markers = raw_markers

        buffer = BytesIO()
        pdf = canvas.Canvas(buffer, pagesize=(page_width, page_height))

        if background_reader is not None:
            pdf.drawImage(
                background_reader,
                0,
                0,
                width=page_width,
                height=page_height,
                preserveAspectRatio=False,
                mask='auto',
            )

        rendered_marker = False

        for marker in markers:
            if not isinstance(marker, dict):
                continue

            key = marker.get('key')
            value = _certificate_field_value(cert, key)
            if not value:
                continue

            x_pct = _clamp_pct(marker.get('xPct'), default=50.0)
            y_pct = _clamp_pct(marker.get('yPct'), default=50.0)

            x = (x_pct / 100.0) * page_width
            y = page_height - ((y_pct / 100.0) * page_height)

            font_size = _parse_font_size(marker.get('fontSize'), default=24)
            align = str(marker.get('align', 'left')).lower()

            pdf.setFont('Helvetica', font_size)
            pdf.setFillColor(_parse_color(marker.get('color')))

            if align == 'center':
                pdf.drawCentredString(x, y, value)
            elif align == 'right':
                pdf.drawRightString(x, y, value)
            else:
                pdf.drawString(x, y, value)

            rendered_marker = True

        if not rendered_marker:
            _draw_default_layout(pdf, cert)

        pdf.showPage()
        pdf.save()
        buffer.seek(0)
        return buffer.getvalue()

    except Exception as err:
        # Absolute fallback: always return a valid minimal PDF.
        print(f"PDF RENDER ERROR: {err}")
        fallback = BytesIO()
        pdf = canvas.Canvas(fallback, pagesize=letter)
        pdf.setFont('Helvetica-Bold', 16)
        pdf.drawString(72, 760, 'Certificate Preview')
        pdf.setFont('Helvetica', 12)
        pdf.drawString(72, 730, f"Certificate ID: {getattr(cert, 'certificate_id', 'N/A')}")
        pdf.drawString(72, 710, f"Name: {getattr(cert, 'full_name', 'N/A')}")
        pdf.drawString(72, 690, f"Course: {getattr(cert, 'course', 'N/A')}")
        pdf.showPage()
        pdf.save()
        fallback.seek(0)
        return fallback.getvalue()


def generate_and_attach_certificate_pdf(cert):
    pdf_bytes = build_certificate_pdf_bytes(cert)
    cert.file.save(
        f"{cert.certificate_id}.pdf",
        ContentFile(pdf_bytes),
        save=True,
    )
    return cert.file