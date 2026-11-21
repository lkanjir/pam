// Bound concurrent collections so Docker resource usage is predictable locally and in CI.
[assembly: CollectionBehavior(MaxParallelThreads = 4)]
