#include "lexer.h"
#include "vector.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

struct input_reader create_input_reader() {
    struct input_reader out = {};
    return out;
}

char assert_input_reader_not_initialized(struct input_reader* irSelf) {
    if (irSelf->pInput == 0) return INPUT_READER_SUCCESS;
    return INPUT_READER_FAIL;
}

char init_input_reader(struct input_reader* irSelf, const char* pFileName, const char* pInput) {
    if (assert_input_reader_not_initialized(irSelf) == INPUT_READER_FAIL) return INPUT_READER_ALREADY_INITIALIZED;

    irSelf->pFileName = pFileName;
    irSelf->pInput = pInput;
    irSelf->uDataLen = strlen(pInput);
    irSelf->uCaret = 0;
    return INPUT_READER_SUCCESS;
}

char get_remaining_bytes(struct input_reader* irSelf, unsigned int* out_iRemainingBytes) {
    if (assert_input_reader_not_initialized(irSelf) == INPUT_READER_SUCCESS) return INPUT_READER_NOT_INITIALIZED;

    *out_iRemainingBytes = irSelf->uDataLen - irSelf->uCaret;
    return INPUT_READER_SUCCESS;
}

char peek_next_char(struct input_reader* irSelf, char* out_pChar) {
    if (assert_input_reader_not_initialized(irSelf) == INPUT_READER_SUCCESS) return INPUT_READER_NOT_INITIALIZED;

    if (irSelf->uCaret >= irSelf->uDataLen) return INPUT_READER_OOB;
    char b = irSelf->pInput[irSelf->uCaret];
    *out_pChar = b;
    return INPUT_READER_SUCCESS;
}

char advance_next_char(struct input_reader* irSelf, char* out_pChar) {
    if (assert_input_reader_not_initialized(irSelf) == INPUT_READER_SUCCESS) return INPUT_READER_NOT_INITIALIZED;
    
    char e = peek_next_char(irSelf, out_pChar);
    if (e != INPUT_READER_SUCCESS) return e;
    irSelf->uCaret++;
    return INPUT_READER_SUCCESS;
}

char allocate_and_read_while(struct input_reader* irSelf, char** ppBuff, unsigned int* iBytesRead, char(*fpPredicate)(char iNext)) {
    unsigned int buffSize = 32;
    *ppBuff = (char*)calloc(buffSize, sizeof(char));
    if (*ppBuff == 0) return INPUT_READER_FAIL;
    unsigned int i = 0;
    char eAdvance = 0;
    while ((eAdvance = advance_next_char(irSelf, &(*ppBuff)[i])) == INPUT_READER_SUCCESS) {
        char ePred = fpPredicate((*ppBuff)[i]);
        if (ePred == INPUT_READER_REJECT) {
            irSelf->uCaret--;
            if (i > 0) {
                *ppBuff = (char*)realloc(*ppBuff, i + 1);
                if (*ppBuff == 0) return INPUT_READER_FAIL;
                (*ppBuff)[i] = '\0';
                *iBytesRead = i;
                return INPUT_READER_SUCCESS;
            } else {
                free(*ppBuff);
                return INPUT_READER_REJECT;
            }
        } else if (ePred != INPUT_READER_SUCCESS /* predicate function totally failed */) {
            free(*ppBuff);
            return ePred;
        }
        i++;
        if (i >= buffSize) {
            buffSize *= 2;
            *ppBuff = (char*)realloc(*ppBuff, buffSize);
            if (*ppBuff == 0) return INPUT_READER_FAIL;
        }
    }
    if (eAdvance == INPUT_READER_OOB) {
        *ppBuff = (char*)realloc(*ppBuff, i + 1);
        if (*ppBuff == 0) return INPUT_READER_FAIL;
        (*ppBuff)[i] = '\0';
        *iBytesRead = i;
        return INPUT_READER_SUCCESS;
    }
    free(*ppBuff);
    return eAdvance;
}

struct read_session create_read_session() {
    struct read_session out = {};
    return out;
}

struct file_input_idx_range create_file_input_idx_range() {
    struct file_input_idx_range out = {};
    return out;
}

struct file_input_idx_range contain_file_input_idx_range(struct file_input_idx_range a, struct file_input_idx_range b) {
    struct file_input_idx_range out = create_file_input_idx_range();
    out.uStartIdx = a.uStartIdx < b.uStartIdx ? a.uStartIdx : b.uStartIdx;
    out.uEndIdx = a.uEndIdx > b.uEndIdx ? a.uEndIdx : b.uEndIdx;
    return out;
}

char assert_read_session_not_initialized(struct read_session* rsSelf) {
    if (rsSelf->irParent == 0) return INPUT_READER_SUCCESS;
    return INPUT_READER_FAIL;
}

char init_read_session(struct read_session* rsSelf, struct input_reader* irParent) {
    if (assert_read_session_not_initialized(rsSelf) == INPUT_READER_FAIL) return INPUT_READER_ALREADY_INITIALIZED;

    rsSelf->irParent = irParent;
    rsSelf->uStartCaret = 0;
    return INPUT_READER_SUCCESS;
}

char open_read_session(struct read_session* rsSelf) {
    if (assert_read_session_not_initialized(rsSelf) == INPUT_READER_SUCCESS) return INPUT_READER_NOT_INITIALIZED;
    rsSelf->uStartCaret = rsSelf->irParent->uCaret;
    return INPUT_READER_SUCCESS;
}

char close_read_session(struct read_session* rsSelf, struct file_input_idx_range* fiirRange) {
    if (assert_read_session_not_initialized(rsSelf) == INPUT_READER_SUCCESS) return INPUT_READER_NOT_INITIALIZED;
    fiirRange->uStartIdx = rsSelf->uStartCaret;
    fiirRange->uEndIdx = rsSelf->irParent->uCaret;
    return INPUT_READER_SUCCESS;
}

char close_and_retreat_read_session(struct read_session* rsSelf) {
    if (assert_read_session_not_initialized(rsSelf) == INPUT_READER_SUCCESS) return INPUT_READER_NOT_INITIALIZED;
    rsSelf->irParent->uCaret = rsSelf->uStartCaret;
    return INPUT_READER_SUCCESS;
}

struct token create_token() {
    struct token out = {};
    return out;
}

char set_token(struct token* tSelf, char iKind, struct file_input_idx_range fiirFileRange, const char* content) {
    tSelf->iKind = iKind;
    tSelf->fiirFileRange = fiirFileRange;
    tSelf->content = content;
    return INPUT_READER_SUCCESS;
}

char get_tokens(const char* pFileName, const char* pInput) {
    struct input_reader reader = create_input_reader();
    init_input_reader(&reader, pFileName, pInput);

    struct read_session session1 = create_read_session();
    init_read_session(&session1, &reader);
    open_read_session(&session1);

    struct vector token_list = create_vector();
    init_vector(&token_list, 500, sizeof(struct token));

    int remainingBytes;
    while (get_remaining_bytes(&reader, &remainingBytes) == INPUT_READER_SUCCESS && remainingBytes > 0) {
        struct token token = create_token();
        char e1 = read_token_ident(&reader, &token);
        if (e1 == INPUT_READER_SUCCESS) continue;
        if (e1 != INPUT_READER_REJECT) return e1;
        
        char e2 = read_token_number(&reader, &token);
        if (e2 == INPUT_READER_SUCCESS) continue;
        if (e2 != INPUT_READER_REJECT) return e2;

        char tmp;
        advance_next_char(&reader, &tmp);
    }

    return INPUT_READER_SUCCESS;
}

char is_digit(char c) {
    return c >= '0' && c <= '9' ? INPUT_READER_SUCCESS : INPUT_READER_REJECT;
}

char is_valid_identifier_char(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || is_digit(c) == INPUT_READER_SUCCESS
        ? INPUT_READER_SUCCESS : INPUT_READER_REJECT; 
}

char read_token_ident(struct input_reader* irReader, struct token* out_tToken) {
    struct read_session wholeIdentifierSession = create_read_session();
    char eInit = init_read_session(&wholeIdentifierSession, irReader);
    if (eInit != INPUT_READER_SUCCESS) return eInit;
    
    char eOpen = open_read_session(&wholeIdentifierSession);
    if (eOpen != INPUT_READER_SUCCESS) return eOpen;

    char* buff = 0;
    unsigned int bytesRead = 0;
    char eReadIdent = allocate_and_read_while(irReader, &buff, &bytesRead, &is_valid_identifier_char);
    if (eReadIdent != INPUT_READER_SUCCESS) {
        close_and_retreat_read_session(&wholeIdentifierSession);
        return eReadIdent;
    }
    if (is_digit(buff[0]) == INPUT_READER_SUCCESS) {
        free(buff);
        close_and_retreat_read_session(&wholeIdentifierSession);
        return INPUT_READER_REJECT;
    }

    struct file_input_idx_range range = create_file_input_idx_range();
    char eClose = close_read_session(&wholeIdentifierSession, &range);
    if (eClose != INPUT_READER_SUCCESS) {
        free(buff);
        close_and_retreat_read_session(&wholeIdentifierSession);
        return INPUT_READER_FAIL;
    }

    char eSet = set_token(out_tToken, TOKEN_KIND_IDENT, range, buff);
    if (eSet != INPUT_READER_SUCCESS) return eSet;
    return INPUT_READER_SUCCESS;
}

char read_token_number_decimal(struct input_reader* irReader, char* pNumberStrBuff, unsigned int iNumberBytesRead, struct file_input_idx_range* fiirDecimalRange) {
    struct read_session decimalSession = create_read_session();
    char eInit2 = init_read_session(&decimalSession, irReader);
    if (eInit2 != INPUT_READER_SUCCESS) return eInit2;
    
    char eOpen2 = open_read_session(&decimalSession);
    if (eOpen2 != INPUT_READER_SUCCESS) return eOpen2;

    char decimalChar;
    char ePeekDecimal = peek_next_char(irReader, &decimalChar);
    if (decimalChar != '.') {
        close_and_retreat_read_session(&decimalSession);
        return INPUT_READER_REJECT;
    }

    advance_next_char(irReader, &decimalChar);
    char* buffDecimal = 0;
    unsigned int bytesReadDecimal = 0;
    char eReadDecimal = allocate_and_read_while(irReader, &buffDecimal, &bytesReadDecimal, &is_digit);
    if (eReadDecimal != INPUT_READER_SUCCESS) {
        close_and_retreat_read_session(&decimalSession);
        if (eReadDecimal != INPUT_READER_REJECT) {
            free(buffDecimal);
            return eReadDecimal;
        }
        return INPUT_READER_REJECT;
    }
    pNumberStrBuff = (char*)realloc(pNumberStrBuff, iNumberBytesRead + 1 + bytesReadDecimal + 1 /* null-term */);
    pNumberStrBuff[iNumberBytesRead] = '.';
    memcpy(pNumberStrBuff + iNumberBytesRead + 1, buffDecimal, bytesReadDecimal);
    free(buffDecimal);
    pNumberStrBuff[iNumberBytesRead + 1 + bytesReadDecimal] = '\0';

    struct file_input_idx_range range = create_file_input_idx_range();
    char eClose2 = close_read_session(&decimalSession, &range);
    if (eClose2 != INPUT_READER_SUCCESS) {
        free(buffDecimal);
        close_and_retreat_read_session(&decimalSession);
        return INPUT_READER_FAIL;
    }
    *fiirDecimalRange = range;
    return INPUT_READER_SUCCESS;
}

char read_token_number(struct input_reader* irReader, struct token* out_tToken) {
    struct read_session wholeNumberSession = create_read_session();
    char eInit = init_read_session(&wholeNumberSession, irReader);
    if (eInit != INPUT_READER_SUCCESS) return eInit;

    char eOpen = open_read_session(&wholeNumberSession);
    if (eOpen != INPUT_READER_SUCCESS) return eOpen;

    char* buff = 0;
    unsigned int bytesRead = 0;
    char eReadNumber = allocate_and_read_while(irReader, &buff, &bytesRead, &is_digit);
    if (eReadNumber != INPUT_READER_SUCCESS) {
        close_and_retreat_read_session(&wholeNumberSession);
        return eReadNumber;
    }

    struct file_input_idx_range decimalRange = create_file_input_idx_range();
    char eReadDecimal = read_token_number_decimal(irReader, buff, bytesRead, &decimalRange);
    if (eReadDecimal != INPUT_READER_SUCCESS && eReadDecimal != INPUT_READER_REJECT) {
        return eReadDecimal;
    }

    struct file_input_idx_range range = create_file_input_idx_range();
    char eClose = close_read_session(&wholeNumberSession, &range);
    if (eReadDecimal == INPUT_READER_SUCCESS) range = contain_file_input_idx_range(range, decimalRange);
    if (eClose != INPUT_READER_SUCCESS) {
        free(buff);
        close_and_retreat_read_session(&wholeNumberSession);
        return INPUT_READER_FAIL;
    }

    char eSet = set_token(out_tToken, TOKEN_KIND_NUMBER, range, buff);
    if (eSet != INPUT_READER_SUCCESS) return eSet;

    printf("Read number %s\n", buff);

    return INPUT_READER_SUCCESS;
}