struct sysinfo {
  uint64 freemem;   // amount of free memory (bytes)
  uint64 nproc;     // number of process
  long load[3];   // average load of [1min, 5min, 15min] * LOAD_FACTOR
  char   load1[6];  // avg load of 1min,  xx.xx format
  char   load5[6];  // avg load of 5min,  xx.xx format
  char   load15[6]; // avg load of 15min, xx.xx format
};
