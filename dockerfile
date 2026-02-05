# Wir nutzen ein schlankes Python Image als Basis
FROM python:3.9-slim

# Arbeitsverzeichnis im Container festlegen
WORKDIR /app

# Abhängigkeiten kopieren und installieren
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Den restlichen Code kopieren
COPY . .

# Ordner für Uploads und DB sicherstellen (falls nicht vorhanden)
RUN mkdir -p static/map_images

# Port 5000 freigeben
EXPOSE 5000

# Startbefehl
CMD ["python", "app.py"]