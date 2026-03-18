# dependency-track-postprocessupdater

This service solves a very specific problem.

As part of our build pipelines we upload SBOMs to Dependency-Track.
This includes settings Tags on the resulting Project, and uploading vulnerability suppressions.

Tags and Suppressions cannot be uploaded to Dependency-Track until the uploaded BOM has been processed,
an asynchronous process that can take a few minutes to complete - blocking the build pipeline
and racking up unnecessary CI minutes.

This service is a workaround for that.

Instead of recording Tags on the Dependency-Track Project, the pipeline registers the Tags 
with this service and finished.
This service is configured within Dependency-Track as a WebHook for the "BOM_PROCESSED" event.
When the event is received, this service will update the Tags on the Dependency-Track Project.

