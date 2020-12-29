/*************************************************************************
>  File Name: test_p.c
>  Author: zxl
>  Mail:
>  Created Time: 2020-12-24 17:58:49
*************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "datatype.h"

#define ID_LEN 11
#define NAME_LEN 11

int main( )
{
    void *   buf = NULL;
    unsigned len;

    /*init*/
    Student stu;
    student__init(&stu);

    School scl;
    school__init(&scl);

    /*set student's value*/
    stu.id   = malloc(ID_LEN);
    stu.name = malloc(NAME_LEN);
    strcpy(stu.name, "answer");
    strcpy(stu.id, "092312125");
    stu.age = 22;

    /*set grade value*/
    Grade gra = GRADE__PRIMARY;

    /*set school value*/
    if (gra >= 0)
    {
        scl.has_grade = 1;
        scl.grade     = gra;
    }
    scl.student = &stu;

    /*packing*/
    len = school__get_packed_size(&scl);
    buf = malloc(len);
    school__pack(&scl, buf);
    // fprintf(stderr, "write %d serialized bytes\n", len);
    fwrite(buf, len, 1, stdout);

    /*freeing*/
    free(buf);
    free(stu.id);
    free(stu.name);
    return 0;
}
