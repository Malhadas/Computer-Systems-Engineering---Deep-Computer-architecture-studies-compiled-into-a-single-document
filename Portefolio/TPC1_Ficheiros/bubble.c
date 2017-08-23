/* File:    bubble.c
 *
 * Purpose: Use bubble sort to sort a list of ints.
 *
 * Compile: gcc -g -Wall -fopenmp -o bubble bubble.c
 * Usage:   bubble <n> <g|i> <num_threads>
 *             n:   number of elements in list
 *            'g':  generate list using a random number generator
 *            'i':  user input list
 *            'num_threads'
 *
 * Input:   list (optional)
 * Output:  sorted list
 *
 * IPP:     Section 3.7.1 (pp. 127 and ff.) and Section 5.6.1
 *          (pp. 232 and ff.)
 */
#include <stdio.h>
#include <stdlib.h>
#include <omp.h>
#include <semaphore.h>
#include <pthread.h>
#include <time.h>
#include <assert.h>

/* For random list, 0 <= keys < RMAX */
const int RMAX = 100;

/* Function prototypes */
void Usage(char* prog_name);
void Get_args(int argc, char* argv[], int* n_p, int* n_t, char* g_i_p);
void Generate_list(int a[], int n);
void Cpy_list(int a[],int b[], int n);
void Print_list(int a[], int n, char* title);
void Read_list(int a[], int n);
void Bubble_sort(int a[], int n);
void Bubble_sort_OMP(int a[], int n);
void Bubble_sort_pthreads();

int num_threads;
/* global variables for pthreads */
long thread;
pthread_t * thread_handles;
pthread_mutex_t * thread_mutexes;

int validate(int *a,int *b,int n){
    int i;    
    for(i=0;i<n;i++)
        if (a[i]!=b[i]) return 0;
    return 1;
}

/*---------------------------------   --------------------------------*/
int main(int argc, char* argv[]) {
   int  n;
   char g_i;
   int* a;
   int* b;
   int* c;
   clock_t start, stop;

   Get_args(argc, argv, &n, &num_threads, &g_i);
   a = (int*) malloc(n*sizeof(int));
   b = (int*) malloc(n*sizeof(int));
   c = (int*) malloc(n*sizeof(int));
   thread_handles = malloc(num_threads *sizeof(pthread_t));
   thread_mutexes = malloc(num_threads *sizeof(pthread_mutex_t));

   for(thread=0;thread<num_threads;thread++)
       pthread_mutex_init(&thread_mutexes[thread],NULL);

   if (g_i == 'g') {
      Generate_list(a, n);
      //Print_list(a, n, "Before sort");
   } else {
      Read_list(a, n);
   }
   Cpy_list(a,b,n);
   Cpy_list(a,c,n);

   double t;

   assert((start=clock())!=-1);
   Bubble_sort(a, n);
   stop = clock();
   t = (double) (stop-start)/(CLOCKS_PER_SEC / 1000);

   //Print_list(a, n, "After sort (sequential)");
   printf("Seq Time: %g\n", t);

   assert((start=clock())!=-1);
   Bubble_sort_OMP(b, n);
   stop = clock();
   t = (double) (stop-start)/(CLOCKS_PER_SEC / 1000);
   //Print_list(b, n, "After sort (OMP)");
   printf("OMP Time: %g, Valid:%d\n", t, validate(a,b,n));

   assert((start=clock())!=-1);
   Bubble_sort_pthreads(c,n);
   stop = clock();
   t = (double) (stop-start)/(CLOCKS_PER_SEC / 1000);

   //Print_list(c, n, "After sort (Pthreads)");
   printf("Pthreads Time: %g, Valid:%d\n",t, validate(a,c,n));

   free(a);
   free(b);
   free(c);
   return 0;
}  /* main */


/*-----------------------------------------------------------------
 * Function:  Usage
 * Purpose:   Summary of how to run program
 */
void Usage(char* prog_name) {
   fprintf(stderr, "usage:   %s <n> <g|i> <num_threads>\n", prog_name);
   fprintf(stderr, "   n:            number of elements in list\n");
   fprintf(stderr, "  'g':           generate list using a random number generator\n");
   fprintf(stderr, "  'i':           user input list\n");
   fprintf(stderr, "  'num_threads': for parallel versions\n");
}  /* Usage */


/*-----------------------------------------------------------------
 * Function:  Get_args
 * Purpose:   Get and check command line arguments
 * In args:   argc, argv
 * Out args:  n_p, g_i_p
 */
void Get_args(int argc, char* argv[], int* n_p, int* num_threads, char* g_i_p) {
   if (argc != 4 ) {
      Usage(argv[0]);
      exit(0);
   }
   *n_p = atoi(argv[1]);
   *num_threads = atoi(argv[3]);
   *g_i_p = argv[2][0];

   if (*n_p <= 0 || (*g_i_p != 'g' && *g_i_p != 'i') ) {
      Usage(argv[0]);
      exit(0);
   }
}  /* Get_args */


/*-----------------------------------------------------------------
 * Function:  Generate_list
 * Purpose:   Use random number generator to generate list elements
 * In args:   n
 * Out args:  a
 */
void Generate_list(int a[], int n) {
   int i;

   srandom(0);
   for (i = 0; i < n; i++)
      a[i] = random() % RMAX;
}  /* Generate_list */


/*-----------------------------------------------------------------
 * Function:  Print_list
 * Purpose:   Print the elements in the list
 * In args:   a, n
 */
void Print_list(int a[], int n, char* title) {
   int i;

   printf("%s:\n", title);
   for (i = 0; i < n; i++)
      printf("%d ", a[i]);
   printf("\n");
}  /* Print_list */


/*-----------------------------------------------------------------
 * Function:  Read_list
 * Purpose:   Read elements of list from stdin
 * In args:   n
 * Out args:  a
 */
void Read_list(int a[], int n) {
   int i;

   printf("Please enter the elements of the list\n");
   for (i = 0; i < n; i++)
      if(!scanf("%d", &a[i])) return;
}  /* Read_list */


/*-----------------------------------------------------------------
 * Function:     Bubble_sort
 * Purpose:      Sort list using bubble sort
 * In args:      n
 * In/out args:  a
 */
void Bubble_sort(
      int  a[]  /* in/out */,
      int  n    /* in     */) {
   int list_length, i, temp;

   for (list_length = n; list_length >= 2; list_length--)
      for (i = 0; i < list_length-1; i++)
         if (a[i] > a[i+1]) {
            temp = a[i];
            a[i] = a[i+1];
            a[i+1] = temp;
         }

}  /* Bubble_sort */

/*-----------------------------------------------------------------
 * Function:     Bubble_sort
 * Purpose:      Sort list using bubble sort
 * In args:      n
 * In/out args:  a
 */
void Bubble_sort_OMP(
      int  a[]  /* in/out */,
      int  n    /* in     */) {
   int list_length, block_count, i, temp;
   int block_size, lower, upper, block;

   block_count = num_threads;
   omp_lock_t m[block_count];
   block_size = n/block_count;

   for(i=0;i<block_count;i++) omp_init_lock(&m[i]);

   omp_set_num_threads(num_threads);
   
   #pragma omp parallel private(list_length, block, lower, upper, i, temp)
   {
       for(list_length=block_size;list_length>=1;list_length--){
           for(block=0;block<block_count;block++){
               lower=block_size*block;
               if(block==block_count-1) upper = n;
               else upper = block_size*(block+1);
               if(block==0) omp_set_lock(&m[0]);

               for(i=lower;i<upper-1;i++){
                   if(a[i]>a[i+1]){
                       temp=a[i];
                       a[i]=a[i+1];
                       a[i+1]=temp;
                   }
               }
               if(block==block_count-1){
                   omp_unset_lock(&m[block]);
                   break;
               }

               omp_set_lock(&m[block+1]);
               if(a[i]>a[i+1]){
                   temp=a[i];
                   a[i]=a[i+1];
                   a[i+1]=temp;
               }
               omp_unset_lock(&m[block]);
           }
        }
    }
} /* Bubble_sort_OMP */

int *arr;
int  num;        

/*-----------------------------------------------------------------
 * Function:     Bubble_pthreads_aux
 * Purpose:      swap list element
 * In args:      i
 */
void* sort_thread(void *param) { 
    int list_length, block_count, i, temp;
    int block_size, lower, upper, block;

    block_count = num_threads;
    block_size = num/block_count;
    pthread_mutex_t *m = thread_mutexes;


    for(list_length = block_size; list_length >= 1; list_length--){
        for(block=0;block<block_count;block++){
            lower = block_size *block;
            if(block==block_count-1) upper = num;
            else upper = block_size*(block+1);
            if(block==0) pthread_mutex_lock(&m[0]);
            for(i=lower;i<upper-1;i++){
                if(arr[i]>arr[i+1]){
                    temp=arr[i];
                    arr[i]=arr[i+1];
                    arr[i+1]=temp;
                }
            }
            if(block==block_count-1){
                pthread_mutex_unlock(&m[block]);
                break;
            }
            pthread_mutex_lock(&m[block+1]);
            if(arr[i]>arr[i+1]){
                temp=arr[i];
                arr[i]=arr[i+1];
                arr[i+1]=temp;
            }
            pthread_mutex_unlock(&m[block]);
        }
    }
    return NULL;
} /*sort_thread*/

/*-----------------------------------------------------------------
 * Function:     Bubble_sort_pthreads
 * Purpose:      Sort list using bubble sort
 */
void Bubble_sort_pthreads(int *aa, int nn) { 
    int ts[num_threads];
    num=nn;
    arr=aa;
    for(thread=0;thread<num_threads;thread++){
        ts[thread]=thread;
        pthread_create(&thread_handles[thread],NULL,sort_thread,(void*)(ts+thread));
    }
    for(thread=0; thread<num_threads;thread++)
        pthread_join(thread_handles[thread],NULL);
    for(thread=0; thread<num_threads; thread++)
        pthread_mutex_destroy(&thread_mutexes[thread]);
}/*Bubble_sort_pthreads*/

void Cpy_list(int a[], int b[], int n){
     int i; 
     for(i=0;i<n;i++) b[i]=a[i];
} /*Cpy_list*/

