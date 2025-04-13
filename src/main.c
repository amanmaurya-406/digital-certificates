#include <stdio.h>
#include <string.h>
#include "RSA_generateKey.h"
#include "utils.h"
#include "encodeKey.h"
#include "createCSR.h"
#include "cer2txt.h"
#include "generate_CA.h"
#include "generateCertificate.h"


void display(){
    const char *options[] = {
        "\n[G] Generate RSA key pair",
        "[C] Certificate Signing Request (CSR)",
        "[S] Generate Self-signed Certificate Authority (CA)",
        "[D] Digital Certificate",
        "[X] Exit"
    };

    int options_size = sizeof(options) / sizeof(options[0]);

    for(int i = 0; i < options_size; i++)
        printf("%s\n", options[i]);
}

void handle_input(const char *prompt, char *buffer, size_t size){
    printf("%s", prompt);
    if(fgets(buffer, size, stdin) != NULL){
        buffer[strcspn(buffer, "\n")] = '\0';
    }
}

DName *get_details(){
    DName *dName = init_dname();
    if(!dName){ return NULL; }

    printf("-----\nEnter information that will be incorporated into your certificate request.\n-----\n");

    handle_input("Country Name (2 letter code) [AU]: ", dName->country, sizeof(dName->country));
    handle_input("State or Province Name: ", dName->state, sizeof(dName->state));
    handle_input("Locality Name: ", dName->city, sizeof(dName->city));
    handle_input("Organization Name: ", dName->org, sizeof(dName->org));
    handle_input("Organization Unit Name: ", dName->unit, sizeof(dName->unit));
    handle_input("Common Name: ", dName->name, sizeof(dName->name));

    return dName;
}


int main(){

    char choice;
    do{
        display();
        printf("Enter your choice: ");
        scanf(" %c", &choice);
        while(getchar() != '\n');

        switch(choice){
            case 'G': case 'g':{    /* Generating RSA keys for subject */
                if(generate_RSA_key(DATA_DIR "/private.key")){
                    printf("Key generated and stored as '%s'\n", "private.key");
                }
                else{
                    printf("Key generation failed\n");
                }
                break;
            }

            case 'C': case 'c':{    /* Certificate signing request */
                PrivateKey *privKey = d2i_RSAPrivateKey(DATA_DIR "/private.key");
                DName *subject = get_details();
                
                CSR *csr = createCSR(privKey, subject);
                if(!csr){ break; }

                csr_cer2txt(DATA_DIR "/csr.cer");

                free_dname(subject);
                free_privateKey(privKey);
                free_csr(csr);
                break;
            }

            case 'S': case 's':{    /* Generating self-signed CA */
                DName *caInfo = get_details();
                Certificate *ca_cert = generateCA(caInfo);
                
                cert_cer2txt(DATA_DIR "/ca_certificate.cer", DATA_DIR "/ca_certificate.txt");
                
                free_dname(caInfo);
                free_certificate(ca_cert);
                
                break;
            }

            case 'D': case 'd':{    /* Generating Digital Certificate */
                CSR *csr = load_csr(DATA_DIR "/csr.cer");
                if(!csr){ 
                    printf("Error loading CSR\n");
                    break;
                }
                
                PrivateKey *ca_privKey = d2i_RSAPrivateKey(DATA_DIR "/ca_private.key");
                if(!ca_privKey){
                    printf("Error loading CA Private Key");
                    break;
                }
                
                Certificate *ca_cert = load_certificate(DATA_DIR "/ca_certificate.cer");
                if(!ca_cert){
                    printf("Error loading CA Certificate");
                    break;
                }
                
                Certificate *certificate = generate_certificate(csr, ca_cert->tbsCert->subject, ca_privKey);
                if(!certificate){
                    printf("Error generating Certificate");
                    break;
                }
                
                cert_cer2txt(DATA_DIR "/issued_certificate.cer", DATA_DIR "/issued_certificate.txt");
                
                free_csr(csr);
                free_privateKey(ca_privKey);
                free_certificate(ca_cert);
                free_certificate(certificate);
                
                break;
            }

            case 'X': case 'x':
                break;
            
            default:
                printf("Wrong choice!\n");
        }
    }while(choice != 'X' && choice != 'x');

    return 0;
}


