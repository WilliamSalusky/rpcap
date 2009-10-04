#define LOG(x,s...) do { \
      time_t t = time(NULL); \
      char *d = ctime(&t); \
      fprintf(stderr,"%.*s %s[%d] %s(): ",\
            (int)strlen(d)-1,d, __FILE__,\
            __LINE__,__FUNCTION__); \
      fprintf(stderr,x,## s); \
} while(0);
