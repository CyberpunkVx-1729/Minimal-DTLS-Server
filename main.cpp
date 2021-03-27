#include <iostream>
#include "DTLS_server.h"

int main()
{
    DTLS_SERVER dtls_serv;
    dtls_serv.setup_server("0.0.0.0", 20000, true);
    dtls_serv.start_server();
    

    printf("hello from %s!\n", "simple_dtls_server");
    return 0;
}
