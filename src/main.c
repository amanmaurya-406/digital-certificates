#include <stdio.h>
#include <string.h>
#include "RSA_generateKey.h"
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

Info get_details(){
    Info info = {0};

    printf("-----\nEnter information that will be incorporated into your certificate request.\n-----\n");

    handle_input("Country Name (2 letter code) [AU]: ", info.country, sizeof(info.country));
    handle_input("State or Province Name: ", info.state, sizeof(info.state));
    handle_input("Locality Name: ", info.locality, sizeof(info.locality));
    handle_input("Organization Name: ", info.organization, sizeof(info.organization));
    handle_input("Common Name: ", info.common_name, sizeof(info.common_name));

    return info;
}


int main(){

    char choice;
    do{
        display();
        printf("Enter your choice: ");
        scanf("%c", &choice);
        while(getchar() != '\n');

        switch(choice){
            case 'G': case 'g':{    /* Generating RSA keys for subject */
                if(generate_RSA_keys(DATA_DIR "/private.key")){
                    printf("Key generated and stored as '%s'\n", "private.key");
                }
                else{
                    printf("Key generation failed\n");
                }
                break;
            }

            case 'C': case 'c':{    /* Certificate signing request */
                PrivateKey *privateKey = load_privateKey(DATA_DIR "/private.key");
                Info subject_info = get_details();
                
                CSR *csr = createCSR(privateKey, subject_info);
                if(!csr){
                    printf("Certificate signing request failed.\n");
                    break;
                }

                csr_cer2txt(DATA_DIR "/csr.cer");

                free_privateKey(privateKey);
                free_csr(csr);
                // privateKey = NULL, csr = NULL;
                break;
            }

            case 'S': case 's':{    /* Generating self-signed CA */
                Info caInfo = get_details();
                Certificate *ca_cert = generateCA(caInfo);
                cert_cer2txt(DATA_DIR "/ca_certificate.cer", DATA_DIR "/ca_certificate.txt");
                free_certificate(ca_cert);
                break;
            }

            case 'D': case 'd':{    /* Generating Digital Certificate */
                CSR *csr = load_csr(DATA_DIR "/csr.cer");
                if(!csr){ 
                    printf("Error loading CSR\n");
                    break;
                }
                
                PrivateKey *ca_privKey = load_privateKey(DATA_DIR "/ca_private.key");
                if(!ca_privKey){
                    printf("Error loading CA Private Key");
                    break;
                }
                
                Certificate *ca_cert = load_certificate(DATA_DIR "/ca_certificate.cer");
                if(!ca_cert){
                    printf("Error loading CA Certificate");
                    break;
                }
                
                Certificate *certificate = generate_certificate(csr, ca_cert->subject, ca_privKey);
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


