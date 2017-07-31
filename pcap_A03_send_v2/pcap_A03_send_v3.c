#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>



/*
char atoh(char *str){
	u_char arr[80];
	strcpy(arr,str);

	int count=0;
	while(1){
		if(arr[count]=='\0')
			break;
		count++;
	}
	
	int sum=0;
	double x=0;
	for(int i=count; i>0; i--){
		sum+=arr[count]*(int)pow(16.0,x);
		x++;
	}

	return sum;
}
*/

int main(int argc, char *argv[]){
	
	u_char dev_str[80];
	strcpy(dev_str,argv[1]);

	printf("Dev: %s\n",dev_str);



	u_char str[80] ;
	strcpy(str,argv[2]);

	u_char str2[80];
	strcpy(str2,argv[3]);


	const char s[2] = ".";
	const char s2[2]=":";
	
	char *token;
	char *token2;

	u_char s_ip[4];
	u_char s_mac[6];

	int i=0;
	
// STRAT : IP ADDRESS
//	printf("=====Token: IP START=======\n");
	token = strtok(str, s);
	while( token != NULL ) 
	{
//	  printf( "%s ", token );
	  s_ip[i]=atoi(token);
	  i++;
	  token = strtok(NULL, s);
	}
//	printf("\n====Token: IP END=====\n");


// START : MAC ADDRESS
//	printf("====Token: MAC START====\n");
	token2=strtok(str2,s2);                
	int k=0;
	while( token2 != NULL ) 
	{
//	  printf( "*%s ", token2 );
	  s_mac[k]=strtol(token2,NULL,16);
	  k++;
	  token2 = strtok(NULL, s2);
//	  printf(" k : %d, s_mac[%d]: %d \n",k,k,s_mac[k]);

	}
//	printf("\n====Token: MAC END====\n");

// PRINT IP
	printf("=======IP=========\n");
	for(int j=0; j<4; j++){
		printf("%d ",s_ip[j]);
	}
	printf("\n");
// PRINT MAC	
	printf("=======MAC========\n");
	for(int l=0; l<6; l++){
		printf("%x ",s_mac[l]);
	}
	printf("\n");

	return 0;
	}

