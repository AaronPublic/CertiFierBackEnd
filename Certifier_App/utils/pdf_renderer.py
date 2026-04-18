# In-memory binary stream (used to build PDF before saving)
from io import BytesIO
from urllib.parse import urljoin

# Used for formatting date fields
from datetime import date, datetime

# Used to save generated PDF to model
from django.core.files.base import ContentFile
from django.conf import settings
from django.urls import reverse

# Color utilities for PDF text
from reportlab.lib import colors

# Default page size
from reportlab.lib.pagesizes import letter

# Converts image file → PDF-readable object
from reportlab.lib.utils import ImageReader

# Core PDF drawing tool
from reportlab.pdfgen import canvas

# For landscape orientation
from reportlab.lib.pagesizes import landscape
from reportlab.graphics.barcode import qr as qr_lib
from reportlab.graphics.shapes import Drawing
from reportlab.graphics import renderPDF


def _clamp_pct(value, default=50.0):
     # Ensures percentage values (xPct, yPct) stay within 0–100
    try:
        pct = float(value)
    except (TypeError, ValueError):
        pct = float(default)
    return max(0.0, min(100.0, pct))


def _parse_font_size(value, default=24):
    # Ensures font size is within reasonable range
    try:
        size = float(value)
    except (TypeError, ValueError):
        size = float(default)
    return max(8.0, min(200.0, size))


def _parse_positive_size(value, default=120.0):
    try:
        size = float(value)
    except (TypeError, ValueError):
        size = float(default)
    return max(24.0, min(500.0, size))


def _parse_positive_pct(value, default=10.0):
    try:
        pct = float(value)
    except (TypeError, ValueError):
        pct = float(default)
    return max(1.0, min(100.0, pct))


def _parse_color(value):
    # Converts hex string (e.g. "#000000") → ReportLab color
    if isinstance(value, str) and value.strip():
        try:
            return colors.HexColor(value.strip())
        except ValueError:
            return colors.black
    return colors.black


def _certificate_field_value(cert, key):
    # Formats certificate fields dynamically based on marker "key"
    date_value = cert.date_issued

    # Normalize date into string format
    if isinstance(date_value, datetime):
        formatted_date = date_value.date().isoformat()
    elif isinstance(date_value, date):
        formatted_date = date_value.isoformat()
    elif date_value is None:
        formatted_date = ''
    else:
        formatted_date = str(date_value)

    # Map marker keys → actual certificate fields
    mapping = {
        'full_name': cert.full_name,
        'course': cert.course,
        'issued_by': cert.issued_by,
        'date_issued': formatted_date,
        'title': cert.title,
        'certificate_id': cert.certificate_id,
    }
    # Return empty if key not found
    return str(mapping.get(key, ''))


def _build_qr_payload(cert):
    encode_mode = str(getattr(settings, 'QR_ENCODE_MODE', 'certificate_id') or 'certificate_id').strip().lower()

    if encode_mode == 'verification_url':
        verify_path = reverse('verify_certificate', kwargs={'certificate_id': cert.certificate_id})
        base_url = str(getattr(settings, 'VERIFICATION_BASE_URL', '') or '').strip()
        if not base_url:
            return verify_path

        if not base_url.endswith('/'):
            base_url = f"{base_url}/"
        return urljoin(base_url, verify_path.lstrip('/'))

    return cert.certificate_id


def _draw_qr_from_marker(pdf, marker, page_width, page_height, verify_url):
    x_pct = _clamp_pct(marker.get('xPct'), default=90.0)
    y_pct = _clamp_pct(marker.get('yPct'), default=88.0)

    width_pct = marker.get('widthPct')
    height_pct = marker.get('heightPct')
    size_pct = marker.get('sizePct')
    size_px = marker.get('size')

    if width_pct is not None and height_pct is not None:
        qr_width = (_parse_positive_pct(width_pct, default=12.0) / 100.0) * page_width
        qr_height = (_parse_positive_pct(height_pct, default=12.0) / 100.0) * page_height
    elif size_pct is not None:
        size_from_pct = (_parse_positive_pct(size_pct, default=16.0) / 100.0) * min(page_width, page_height)
        qr_width = size_from_pct
        qr_height = size_from_pct
    else:
        size = _parse_positive_size(size_px, default=min(page_width, page_height) * 0.16)
        qr_width = size
        qr_height = size

    x = (x_pct / 100.0) * page_width
    y = page_height - ((y_pct / 100.0) * page_height)

    qr_width = _parse_positive_size(qr_width)
    qr_height = _parse_positive_size(qr_height)

    widget = qr_lib.QrCodeWidget(verify_url)
    bounds = widget.getBounds()
    x1, y1, x2, y2 = bounds
    drawing = Drawing(qr_width, qr_height, transform=[
        qr_width / (x2 - x1),
        0,
        0,
        qr_height / (y2 - y1),
        -x1 * qr_width / (x2 - x1),
        -y1 * qr_height / (y2 - y1),
    ])
    drawing.add(widget)

    # Marker coordinates are treated as top-left anchor for consistency with text marker UX.
    renderPDF.draw(drawing, pdf, x, y - qr_height)


def _draw_default_qr(pdf, page_width, page_height, verify_url):
    default_size = min(page_width, page_height) * 0.16
    marker = {
        'xPct': 90.0,
        'yPct': 88.0,
        'size': default_size,
    }
    _draw_qr_from_marker(pdf, marker, page_width, page_height, verify_url)


def _draw_default_layout(pdf, cert):
    # Fallback layout if no markers are defined
    pdf.setFont('Helvetica', 14)
    pdf.setFillColor(colors.black)
    pdf.drawString(100, 750, f"Certificate ID: {cert.certificate_id}")
    pdf.drawString(100, 720, f"Name: {cert.full_name}")
    pdf.drawString(100, 690, f"Course: {cert.course}")
    pdf.drawString(100, 660, f"Issued By: {cert.issued_by}")
    pdf.drawString(100, 630, f"Date: {cert.date_issued}")


def _load_background_reader(template):
    # Loads background image from template for use in PDF
    if not (template and template.background and template.background.name):
        return None, None, None

    try:
        # Get actual file path
        image_path = template.background.path  # IMPORTANT

        # Convert to ReportLab-compatible object
        reader = ImageReader(image_path)

        # Get image dimensions
        width, height = reader.getSize()

        return reader, width, height

    except Exception as e:
        print("BACKGROUND LOAD ERROR:", e)
        return None, None, None

def build_certificate_pdf_bytes(cert):
    # Get linked template
    template = cert.template

    # Placeholder positions
    markers = []

    # Background image object
    background_reader = None

    # Default page size
    page_width, page_height = letter

    # Load background image
    bg_reader, bg_width, bg_height = _load_background_reader(template)
    if bg_reader is not None and bg_width and bg_height:
        background_reader = bg_reader

        # Auto-adjust orientation (landscape if width > height)
        if bg_width > bg_height:
            page_width, page_height = landscape((bg_width, bg_height))
        else:
            page_width, page_height = bg_width, bg_height
    else:
        page_width, page_height = letter  # fallback safety

        # Load placeholder markers from template JSON
    if template and isinstance(template.placeholders, dict):
        raw_markers = template.placeholders.get('markers', [])
        if isinstance(raw_markers, list):
            markers = raw_markers

    # Create PDF in memory
    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=(page_width, page_height))

    # Draw background image (if available)
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

    # Track if any text is drawn
    rendered_marker = False
    qr_drawn = False
    verify_url = _build_qr_payload(cert)

    # Loop through all markers (dynamic positioning)
    for marker in markers:
        if not isinstance(marker, dict):
            continue

        key = marker.get('key')

        if key == 'qr_code':
            _draw_qr_from_marker(pdf, marker, page_width, page_height, verify_url)
            qr_drawn = True
            continue

        value = _certificate_field_value(cert, key)
        if not value:
            continue
        
         # Convert percentage → actual coordinates
        x_pct = _clamp_pct(marker.get('xPct'), default=50.0)
        y_pct = _clamp_pct(marker.get('yPct'), default=50.0)

         # Style settings
        x = (x_pct / 100.0) * page_width
        y = page_height - ((y_pct / 100.0) * page_height)

        font_size = _parse_font_size(marker.get('fontSize'), default=24)
        align = str(marker.get('align', 'left')).lower()

        pdf.setFont('Helvetica', font_size)
        pdf.setFillColor(_parse_color(marker.get('color')))

        # Draw text with alignment
        if align == 'center':
            pdf.drawCentredString(x, y, value)
        elif align == 'right':
            pdf.drawRightString(x, y, value)
        else:
            pdf.drawString(x, y, value)

        rendered_marker = True

    # If no markers rendered → fallback layout
    if not rendered_marker:
        _draw_default_layout(pdf, cert)

    if not qr_drawn:
        _draw_default_qr(pdf, page_width, page_height, verify_url)

     # Finalize PDF
    pdf.showPage()
    pdf.save()
    buffer.seek(0)
    # Return PDF as bytes
    return buffer.getvalue()


def generate_and_attach_certificate_pdf(cert):
     # Generate PDF bytes
    pdf_bytes = build_certificate_pdf_bytes(cert)
    # Save PDF to model file field
    cert.file.save(
        f"{cert.certificate_id}.pdf",
        ContentFile(pdf_bytes),
        save=True,
    )
    # Return saved file reference
    return cert.file