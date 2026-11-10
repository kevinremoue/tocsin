# One release in production per project: the last one pushed

An accepted upload declares a successfully deployed production release, not a candidate or a guess based on build order. Each project has one production release: the last accepted upload wins, including re-uploading an older version for a rollback; callers must serialize deployments and uploads. Monitoring is not a pre-deployment gate. Several independently deployed production lines must use separate projects rather than multiple active versions within one project.
