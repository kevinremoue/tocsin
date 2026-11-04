# Serverless on Cloud Run

Cloud Run is Tocsin's reference serverless target: the server scales to zero between requests, and the periodic jobs run as Cloud Run jobs triggered by Cloud Scheduler. Tocsin's small image and sub-second startup keep cold starts short.

The same approach works on other platforms that run containers on demand (Azure Container Apps, Knative, AWS Lambda with the [Lambda Web Adapter](https://github.com/awslabs/aws-lambda-web-adapter)).

The commands below use these variables:

```sh
PROJECT=my-gcp-project
REGION=europe-west1
IMAGE=$REGION-docker.pkg.dev/$PROJECT/tocsin/tocsin:latest
```

## 1. A Postgres database

Any Postgres reachable from Cloud Run works:

- **Cloud SQL for PostgreSQL**: connect through the Cloud SQL socket, with `DATABASE_URL=postgres://tocsin:PASSWORD@/tocsin?host=/cloudsql/PROJECT:REGION:INSTANCE` and `--add-cloudsql-instances PROJECT:REGION:INSTANCE` on the service and jobs.
- **A serverless Postgres** such as Neon: use the provider's connection string, with `sslmode=require`.

Mind connections: each instance opens up to `TOCSIN_DB_MAX_CONNECTIONS` (5 by default), so `--max-instances` × 5 must stay under the database's limit.

## 2. Secrets and image

Store the secrets in Secret Manager, then build the image:

```sh
printf '%s' 'postgres://…' | gcloud secrets create tocsin-database-url --data-file=-
openssl rand -hex 32 | tr -d '\n' | gcloud secrets create tocsin-admin-token --data-file=-
printf '%s' 'https://chat.googleapis.com/v1/spaces/…' | gcloud secrets create tocsin-google-chat --data-file=-

gcloud artifacts repositories create tocsin --repository-format=docker --location=$REGION
gcloud builds submit --tag $IMAGE
```

## 3. Migrations as a job

Run migrations as a Cloud Run job, before each deployment of a new version:

```sh
gcloud run jobs create tocsin-migrate --image $IMAGE --region $REGION --args migrate \
  --set-secrets DATABASE_URL=tocsin-database-url:latest
gcloud run jobs execute tocsin-migrate --region $REGION --wait
```

## 4. The service

```sh
gcloud run deploy tocsin --image $IMAGE --region $REGION \
  --allow-unauthenticated \
  --min-instances 0 --max-instances 4 --memory 256Mi --cpu 1 --cpu-boost \
  --set-env-vars TOCSIN_MIGRATE_ON_START=false,TOCSIN_PUBLIC_URL=https://tocsin.example.com \
  --set-secrets DATABASE_URL=tocsin-database-url:latest,TOCSIN_ADMIN_TOKEN=tocsin-admin-token:latest,TOCSIN_GOOGLE_CHAT_WEBHOOK=tocsin-google-chat:latest
```

- `--allow-unauthenticated` lets CI pipelines reach the API: Tocsin authenticates every request itself (project tokens, admin token for the dashboard and admin API). Alternatively, keep the service private and put it behind IAP or a load balancer.
- Leave `TOCSIN_SCHEDULER` unset: the jobs run separately (next step).
- The SBOM push matches components within the request, for at most 60 seconds; Cloud Run's default request timeout (300 s) leaves room. Send SBOMs gzip-compressed to stay under Cloud Run's 32 MB request limit.

## 5. The jobs

Create one Cloud Run job per periodic task, then trigger them with Cloud Scheduler:

```sh
for job in kev-sync refresh epss-sync; do
  gcloud run jobs create tocsin-$job --image $IMAGE --region $REGION --args $job \
    --set-secrets DATABASE_URL=tocsin-database-url:latest,TOCSIN_GOOGLE_CHAT_WEBHOOK=tocsin-google-chat:latest \
    --set-env-vars TOCSIN_PUBLIC_URL=https://tocsin.example.com
done

SA=tocsin-scheduler@$PROJECT.iam.gserviceaccount.com
gcloud iam service-accounts create tocsin-scheduler
for job in kev-sync refresh epss-sync; do
  gcloud run jobs add-iam-policy-binding tocsin-$job --region $REGION \
    --member serviceAccount:$SA --role roles/run.invoker
done

gcloud scheduler jobs create http tocsin-kev-sync --location $REGION --schedule "0 */6 * * *" \
  --uri "https://run.googleapis.com/v2/projects/$PROJECT/locations/$REGION/jobs/tocsin-kev-sync:run" \
  --http-method POST --oauth-service-account-email $SA
gcloud scheduler jobs create http tocsin-refresh --location $REGION --schedule "30 3 * * *" \
  --uri "https://run.googleapis.com/v2/projects/$PROJECT/locations/$REGION/jobs/tocsin-refresh:run" \
  --http-method POST --oauth-service-account-email $SA
gcloud scheduler jobs create http tocsin-epss-sync --location $REGION --schedule "0 14 * * *" --time-zone UTC \
  --uri "https://run.googleapis.com/v2/projects/$PROJECT/locations/$REGION/jobs/tocsin-epss-sync:run" \
  --http-method POST --oauth-service-account-email $SA
```

FIRST publishes EPSS scores shortly after 13:30 UTC, hence the 14:00 UTC schedule.

Jobs send alerts too (new KEV entries, new advisories, EPSS scores above the threshold), so they need the webhook and the public URL.

A simpler alternative is a Cloud Scheduler HTTP job calling `POST https://tocsin.example.com/api/jobs/kev-sync` with an `Authorization: Bearer <admin token>` header. It needs no Cloud Run job, but the admin token is then stored in the scheduler's configuration, and the job runs inside a request, bound by the request timeout.

## Cost

With `--min-instances 0`, the service costs nothing while idle: you pay for the requests (SBOM pushes, dashboard views) and a few short job runs per day, plus the database.
