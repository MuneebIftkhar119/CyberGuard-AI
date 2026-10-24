#!/usr/bin/env bash
# Render build step: install deps, collect static files, run migrations,
# and (optionally) create an admin user from env vars.
set -o errexit

pip install --upgrade pip
pip install -r requirements.txt

python manage.py collectstatic --no-input
python manage.py migrate --no-input

# Free tiers have no shell, so the first admin is created from env vars.
# Set DJANGO_SUPERUSER_USERNAME, DJANGO_SUPERUSER_EMAIL and DJANGO_SUPERUSER_PASSWORD
# once, deploy, then you can remove them. Re-runs are harmless.
if [[ -n "${DJANGO_SUPERUSER_USERNAME:-}" && -n "${DJANGO_SUPERUSER_PASSWORD:-}" ]]; then
  python manage.py createsuperuser --no-input || echo "Superuser already exists — skipping."
fi
