# dependency-track-postprocessupdater

This service solves a very specific problem.

As part of our build pipelines we upload SBOMs to Dependency-Track.
This includes setting project metadata and tags, granting team access, and uploading vulnerability suppressions.

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
   - The pipeline sends the project name, version, and desired post-processing to this service.
   - The registration is stored on disk, keyed by project name and version.
   - If the same project is registered again, the latest registration wins.
   - The service looks up the project and applies the registration immediately if it has a last BOM import timestamp. 
     The registration remains stored.

2. **Upload the SBOM**
   - The pipeline uploads the SBOM to Dependency-Track as usual.
   - It does not wait for BOM processing to complete.

3. **Webhook-driven completion**
   - Dependency-Track sends a webhook once BOM processing is complete.
   - This service looks up the stored registration by project name and version.
   - It applies the registered changes to the project.
   - On success, the notification time is recorded; the registration remains available for subsequent uploads.

## Design goals

- **No database**
- **Low file churn**
- **Idempotent webhook handling**
- **Fast pipeline completion**
- **Simple operational model**

This means:

- duplicate registrations are fine
- duplicate webhook deliveries are fine
- repeated webhook deliveries reapply the registered changes

## Storage model

Registrations are stored by project name and version in the configured storage directory.

Example lifecycle:
```
POST /register -> stores registration by name and version
POST /webhook -> reads registration -> applies post-processing -> records notification time
```


## Endpoints

### `POST /register`

Registers the post-processing actions for a project.

Expected payload includes:
- project name and version
- optional description, properties, and team UUIDs
- tags
- suppressions

Example:

```json
{
  "name": "example",
  "version": "1.0",
  "description": "Example project",
  "properties": [{"groupName": "build", "propertyName": "source", "propertyValue": "CI", "propertyType": "STRING"}],
  "teams": ["team-uuid"],
  "tags": ["production"]
}
```

Omitting `description` leaves it unchanged; an empty string clears it. Properties are upserted by group and name (new properties default to type `STRING`), and team UUIDs are added to project access without removing existing teams. Updating an existing property changes its value; its type and description are set when it is created. The API key needs portfolio and access-management permissions for these operations.

The service reads the current settings and skips writes that would make no change. Team checks require access-management read permission, and suppression checks require permission to read analyses; read failures stop processing rather than assuming a match.

Registration returns `202` after storing it and, when a project has a nonzero `lastBomImport`, applying it immediately. A missing project or import timestamp leaves it for a later webhook. The timestamp is a best-effort readiness signal: it does not rule out a newer BOM still processing. Lookup or processing failures return `500`, but the registration remains stored for retry or a future webhook; changes may already be partially applied. Project lookup requires `VIEW_PORTFOLIO`.

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


## Compatibility

This service has been tested with:
* Dependency-Track v4.14.x (maintenance mode)
* Dependency-Track v5.x (active development)

The service uses the `/api/v1/` REST API endpoints which are supported in both versions.
