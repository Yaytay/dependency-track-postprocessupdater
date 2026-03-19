# dependency-track-postprocessupdater

This service solves a very specific problem.

As part of our build pipelines we upload SBOMs to Dependency-Track.
This includes setting tags on the resulting project, and uploading vulnerability suppressions.

Tags and suppressions cannot be uploaded to Dependency-Track until the uploaded BOM has been processed,
an asynchronous process that can take a few minutes to complete — blocking the build pipeline
and racking up unnecessary CI minutes.

This service is a workaround for that.

Instead of writing tags and suppressions directly to the Dependency-Track project during the pipeline,
the pipeline registers the desired post-processing with this service and then finishes.
This service is configured within Dependency-Track as a webhook target for the `BOM_PROCESSED` event.
When the event is received, this service updates the project in Dependency-Track.

## How it works

The pipeline uses two steps:

1. **Register post-processing**
   - The pipeline sends the project UUID, tags, and suppressions to this service.
   - The registration is stored on disk, using the project UUID as the filename.
   - If the same project is registered again, the latest registration wins.

2. **Upload the SBOM**
   - The pipeline uploads the SBOM to Dependency-Track as usual.
   - It does not wait for BOM processing to complete.

3. **Webhook-driven completion**
   - Dependency-Track sends a webhook once BOM processing is complete.
   - This service looks up the stored registration for the project UUID.
   - It applies the tags and suppressions to the project.
   - On success, the registration file is deleted.

## Design goals

- **No database**
- **Low file churn**
- **Idempotent webhook handling**
- **Fast pipeline completion**
- **Simple operational model**

This means:

- duplicate registrations are fine
- duplicate webhook deliveries are fine
- if a webhook arrives after processing has already completed, it is treated as a no-op

## Storage model

Registrations are stored as one file per project UUID in the configured storage directory.

Example lifecycle:
```
text POST /register -> writes <storage-dir>/<project-uuid>.json
POST /webhook -> reads <storage-dir>/<project-uuid>.json -> applies post-processing -> deletes the file
```


## Endpoints

### `POST /register`

Registers the post-processing actions for a project.

Expected payload includes:
- project UUID
- tags
- suppressions

### `POST /webhook`

Receives Dependency-Track webhook events.

Expected payload includes the project UUID for the processed BOM.

## Configuration

The service can be configured with flags or environment variables.

Common settings include:

- HTTP listen address
- metrics path
- Dependency-Track address
- Dependency-Track API key
- storage directory
- client request timeout
- log level
- log format

Usage:
```
A stdlib-only Dependency-Track post-processing updater.

Flags:
  --help                           Show context-sensitive help.
  --web.listen-address=:9916       Address to listen on.
  --web.metrics-path=/metrics      Path for metrics.
  --storage.dir=DIR                Directory for registration files.
  --dtrack.address=ADDR            Dependency-Track server address
                                   (default: http://localhost:8080 or $DEPENDENCY_TRACK_ADDR)
  --dtrack.api-key=KEY             Dependency-Track API key
                                   (default: $DEPENDENCY_TRACK_API_KEY)
  --log.level=info                 Only log messages with the given severity or above.
                                   One of: debug, info, warn, error
  --log.format=logfmt              Output format of log messages.
                                   One of: logfmt, json
  --client-request-timeout=10s     Timeout value for client requests to Dependency-Track.
  --version                        Show application version.
```

## Typical pipeline flow

