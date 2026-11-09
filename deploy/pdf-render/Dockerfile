# pdf-render: WeasyPrint behind a small HTTP API (see app.py). Internal only: publish no port.
#   docker build -t pdf-render deploy/pdf-render
#   docker run --rm -e FILES_URL=http://files-serve:8103 --network servers_default --network-alias pdf-render pdf-render
FROM python:3.12-slim-bookworm

# Pango for WeasyPrint's text layout; fonts that cover Latin, the rupee sign and Indic scripts
# (Noto), metric-compatible Arial/Times/Courier (Liberation), DejaVu and Inter as fallbacks,
# because templates' web fonts (Google Fonts) are not fetched.
# Word templates (docx_render.py): LibreOffice Writer without its GUI, and metric-compatible stand-ins
# for common Office fonts (URW base35: Bookman Old Style, Century Schoolbook, Palatino; Carlito:
# Calibri; Caladea: Cambria), mapped by fonts.conf so page breaks stay close to Word's.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0 fontconfig \
        fonts-noto-core fonts-liberation2 fonts-dejavu-core fonts-inter \
        libreoffice-writer-nogui fonts-urw-base35 fonts-crosextra-carlito fonts-crosextra-caladea \
    && rm -rf /var/lib/apt/lists/*
COPY fonts.conf /etc/fonts/conf.d/30-office-aliases.conf
RUN fc-cache -f

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py docx_render.py docx_edit.py docx_filters.py pdf_stamp.py pdf_seal.py test_app.py test_docx.py test_docx_edit.py test_pdf_seal.py ./

RUN useradd --system --uid 65532 --no-create-home render
USER 65532
ENV PORT=8120 PYTHONUNBUFFERED=1 HOME=/tmp
EXPOSE 8120
HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
    CMD python -c "import urllib.request,os; urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ['PORT'], timeout=2)"
CMD ["python", "app.py"]
