static __attribute__ (( always_inline ) ) size_t read_path_data ( struct path * path , struct path_data * pd ) {
    u8 slash = '/';
    u8 zero = 0;
    u32 buf_off = ( MAX_PATH_LEN >> 1) ;
    unsigned int len ;
    unsigned int off ;
    int sz ;

    struct path f_path ;
    bpf_probe_read (& f_path , sizeof ( f_path ) , path ) ;
    struct dentry * dentry = f_path . dentry ;
    struct dentry * d_parent ;
    struct qstr d_name ;

    # pragma unroll
    for ( int i = 0; i < MAX_PATH_DEPTH ; i ++) {
        // break if we ’ ve reached root
        d_parent = BPF_CORE_READ ( dentry , d_parent ) ;
        if ( dentry == d_parent ) break ;

        d_name = BPF_CORE_READ ( dentry , d_name ) ;

        len = ( d_name . len + 1) & ( MAX_DNAME_LEN - 1) ;
        off = buf_off - len ; // read current path starting at buf_off - len
        sz = 0;
        if ( off <= buf_off ) { // catch underflow
            len = len & (( MAX_PATH_LEN >> 1) - 1) ;
            sz = bpf_probe_read_str ( &( pd - > buf [ off & (( MAX_PATH_LEN >> 1) - 1) ]), len , ( void *) d_name . name) ;
        } else break ;

        if ( sz > 1) {
            buf_off -= 1;
            bpf_probe_read (&( pd - > buf [ buf_off & ( MAX_PATH_LEN - ) ]) , 1 , & slash ) ;
            buf_off -= sz - 1;
        } else break ; // path should not be null or empty

        dentry = d_parent ;
    }
