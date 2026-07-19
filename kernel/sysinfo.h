struct sysinfo {
  uint64 freemem;   // amount of free memory (bytes)
  uint64 nproc;     // number of process
  uint64 load[3];   // average load of 1min, 5min, 15min
};
