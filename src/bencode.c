#include <bencode.h>
#include <stdio.h>
#include <string.h>
void bencode_value_free(struct bencode_value *value)
{
   switch (value->type) {
        case BENCODE_MAP: {
            free(value->dictionary);
            value->dictionary = NULL;
            value->dictionary_size=0;
            return;
        }
        case BENCODE_STR: {
            free(value->string);
            value->string = NULL;
            return;
        }
        case BENCODE_INT: {
            value->number=0;
            return;
        }
        default: {
            if (NULL!=value->next) {
                bencode_value_free(value->next);
                free(value->next);
            }
            if (NULL!=value->contained) {
                bencode_value_free(value->contained);
                free(value->contained);
            }
            value->contained = NULL;
            value->next = NULL;
        }

        break;
    }
}

size_t bencode_value_decode(struct bencode_value *value, const char *enc_val, size_t n)
{
//initialize all the values to avoid undefined behaviour
    value->type=4;
    value->string=NULL;
    value->number=0;
    value->next=NULL;
    value->contained=NULL;
    value->dictionary=NULL;
    value->dictionary_size=0;
    //contains all the logic regarding the decoding of encoded_val into a value
    switch (enc_val[0])
    {
        case 'i':{
            value->type= BENCODE_INT;
            int i=1;
            if ('0'==enc_val[i] && 'e'!=enc_val[i+1]){return 0;}
            for (i=1; i<n && enc_val[i]!='e'; i++) {
                if (1==i && enc_val[i]=='-') {continue;}
                if (enc_val[i]<'0' ||  enc_val[i]>'9') {return 0;}
            }
            if (enc_val[i]!='e') {return 0;}
            char strlength[i];
            strncpy(strlength,enc_val +1,i);
            strlength[i-1]='\0';
            value->number=strtoll(strlength, NULL, 10);
            return i+1;
        }
            break;
        case 'l': {
            value->type= BENCODE_LIST;
            int i=1;
            struct bencode_value *temp =NULL;
            while (i<n && enc_val[i]!='e'){
                struct bencode_value *node =malloc(sizeof(struct bencode_value));
                if (n<=i){return 0;}
                int read= bencode_value_decode(node, enc_val+i,n-i);
                if (0==read) {return 0;}
                i+=read;
                if (NULL!=temp) {
                    temp->next=node;
                }
                else {
                    value->contained=node;
                }
                temp=node;
            }
            if ('e'!=enc_val[i]) {return 0;}
            return i+1;

        }

        case 'd': {
            value->type= BENCODE_MAP;
            int i=1;
            int count=0;
            char* prev_key=NULL;
            while (i<n-1 && enc_val[i]!='e') {
                count++;
                if (NULL==value->dictionary) {
                    value->dictionary=malloc(sizeof(struct bencode_value *));
                }
                else {
                    prev_key=value->dictionary[count-2]->key.string;
                    struct bencode_pair** old_dic=value->dictionary;
                    value->dictionary=malloc(count*sizeof(struct bencode_value *));
                    for (int y=0; y<count - 1; y++) {
                        value->dictionary[y]=old_dic[y];
                    }
                    free(old_dic);
                }
                struct bencode_pair* new=malloc(sizeof(struct bencode_pair));
                value->dictionary[count-1]=new;
                if (n<=i) {
                    return 0;
                }
                int read= bencode_value_decode(&(new->key), enc_val+i,n-i);
                if (0==read|| BENCODE_STR!=bencode_value_type(&new->key)) {
                    return 0;
                }
                i+=read;
                if (n<=i) {
                    return 0;
                }
                read= bencode_value_decode(&(new->value), enc_val+i,n-i);
                if (0==read) {
                    return 0;
                }
                i+=read;
                if (NULL!=prev_key&& strcmp(prev_key,new->key.string)>=0) {
                    continue;
                }
            }
            value->dictionary_size=count;
            if ('e'!=enc_val[i]) {return 0;}
            return i+1;

        }
        default:
            if (enc_val[0]<='9' && enc_val[0]>='0') {
                value->type=BENCODE_STR;
                int i=0;
                for (i=0; i<n && enc_val[i]!=':'; i++) {
                    if (enc_val[i]<'0' ||  enc_val[i]>'9') {return 0;}
                }
                char strlength[i+1];
                strncpy(strlength,enc_val,i);
                strlength[i]='\0';
                int istrlength=atoi(strlength);
                value->stringlen=istrlength;
                if (istrlength+i+1>n) {
                    return 0;
                }
                value->string=malloc((1+istrlength)*sizeof(char));
                memcpy(value->string,enc_val+i+1,istrlength*sizeof(char));
                value->string[istrlength]='\0';
                return i+1+istrlength;
            }
    }

    return 0;
}

size_t bencode_value_encode(const struct bencode_value *value, char *buf, size_t n)
{
if (NULL!=buf) {
        size_t parrot=bencode_value_encode(value,NULL,0);
        if (n<parrot) {
            return 0;
        }
    }
    //helped in the debug by: Pasquale Polverino
    switch (value->type) {
        case BENCODE_INT: {
            int l=1;
            if (value->number>=0) {
                //counts the number of digits in a number
                long long temp=value->number;
                while(temp>9){ l++; temp/=10; }
                if (NULL!=buf) {
                    char str[l+2];
                    sprintf(str, "i%llde", value->number);
                    memcpy(buf,str,l+2);
                }
                int next=0;
                if (NULL!=value->next) {
                    if (n!=0 && n<=l+2) {
                        return 0;
                    }
                    next= bencode_value_encode(value->next,(NULL==buf)?buf:buf+l+2,n-l-2);
                    if (next==0) {
                        return 0;
                    }
                }
                return l+2+next;
            }
            long long temp=-value->number;
            while(temp>9){ l++; temp/=10; }
            if (NULL!=buf) {
                char str[l+3];
                sprintf(str, "i%llde", value->number);
                memcpy(buf,str,l+3);
            }
            int next=0;
            if (NULL!=value->next) {
                if (n!=0 && n<=l+3) {
                    return 0;
                }
                next= bencode_value_encode(value->next,(NULL==buf)?buf:buf+l+3,n-l-3);
                if (next==0) {
                    return 0;
                }
            }
            return l+3+next;
        }
        case BENCODE_STR: {
            int l=1;
            long long temp=value->stringlen;
            while(temp>9){ l++; temp/=10; }
            if (NULL!=buf) {
                int n = sprintf(buf, "%d:", value->stringlen);
                memcpy(buf + n,value->string, value->stringlen);
            }
            int next=0;
            if (NULL!=value->next) {
                if (n!=0 && n<=l+1+value->stringlen) {
                    return 0;
                }
                next= bencode_value_encode(value->next,(NULL==buf)?buf:buf+l+1+value->stringlen,n-(l+1+value->stringlen));
                if (next==0) {
                    return 0;
                }
            }
            return l+1+value->stringlen+next;
        }
        case BENCODE_LIST:{
            int elements=0;
            if (NULL!=buf) {
                buf[0]='l';
                elements=bencode_value_encode(value->contained,buf+1,n-2);
                buf[elements+1]='e';
            }
            else {
                elements=bencode_value_encode(value->contained,buf,n-2);
            }
            int next=0;
            if (NULL!=value->next) {
                if (n!=0 && n<=elements+2) {
                    return 0;
                }
                next= bencode_value_encode(value->next,(NULL==buf)?buf:buf+elements+2,n-(elements+2));
                if (next==0) {
                    return 0;
                }
            }
            return elements+2+next;
        }
        default: {
            int elements=0;
            if (NULL!=buf) {
                buf[0]='d';
                for (int i=0;i<value->dictionary_size;i++) {
                    elements+=bencode_value_encode(&value->dictionary[i]->key,buf+elements+1,n-2-elements);
                    elements+=bencode_value_encode(&value->dictionary[i]->value,buf+elements+1,n-2-elements);
                }
                buf[elements+1]='e';
            }
            else {
                for (int i=0;i<value->dictionary_size;i++) {
                    elements+=bencode_value_encode(&value->dictionary[i]->key,NULL,n-2-elements);
                    elements+=bencode_value_encode(&value->dictionary[i]->value,NULL,n-2-elements);
                }
            }
            int next=0;
            if (NULL!=value->next) {
                if (n!=0 && n<=elements+2) {
                    return 0;
                }
                next= bencode_value_encode(value->next,(NULL==buf)?buf:buf+elements+2,n-(elements+2));
                if (next==0) {
                    return 0;
                }
            }
            return elements+2+next;

        }

    }
    return 0;
}

enum bencode_t bencode_value_type(const struct bencode_value *value)
{
    return value->type;
}

size_t bencode_value_len(const struct bencode_value *value)
{
    switch (value->type) {
        case BENCODE_INT:
            return sizeof(long long);
        case BENCODE_STR:
            return value->stringlen;
        case BENCODE_LIST: {
            int i=0;
            struct bencode_value *temp =value->contained;
            while (NULL != temp) {
                i++;
                temp=temp->next;
            }
            return i;
        }
        case BENCODE_MAP: {
            return value->dictionary_size;
        }
        default:
            return 0;

    }
}

long long bencode_value_int(const struct bencode_value *value)
{
     return value->number;
}

const char *bencode_value_str(const struct bencode_value *value)
{
    return value->string;
}

const struct bencode_value *bencode_list_get(const struct bencode_value *value, size_t i)
{
    struct bencode_value *temp=value->contained;
    while (i>0 && NULL!=temp) {
        temp=temp->next;
        i--;
    }
    return temp;
}

const struct bencode_pair *bencode_map_lookup(const struct bencode_value *value, const char *key)
{
    for(int i=0;i<value->dictionary_size;i++) {
        if (!strcmp(key,value->dictionary[i]->key.string)) {
            return value->dictionary[i];
        }
    }
    return NULL;
}
