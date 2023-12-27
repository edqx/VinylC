#include "lexer.h"
#include "vector.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

struct lexer_defect create_lexer_defect() {
    struct lexer_defect out = {};
    return out;
}

char assert_lexer_defect_not_initialized(struct lexer_defect* ldSelf) {
    return ldSelf->irReader == 0 ? INPUT_READER_SUCCESS : INPUT_READER_FAIL;
}

char init_lexer_defect(struct lexer_defect* ldSelf, struct input_reader* irReader) {
    if (assert_lexer_defect_not_initialized(ldSelf) == INPUT_READER_FAIL) return INPUT_READER_ALREADY_INITIALIZED;

    ldSelf->irReader = irReader;
    return INPUT_READER_SUCCESS;
}

char assert_lexer_defect_not_raised(struct lexer_defect* ldSelf) {
    return ldSelf->bRaised == 0 ? INPUT_READER_SUCCESS : INPUT_READER_FAIL;
}

char raise_lexer_defect(struct lexer_defect* ldSelf, unsigned int uDefectCode) {
    if (assert_lexer_defect_not_initialized(ldSelf) == INPUT_READER_SUCCESS) return INPUT_READER_NOT_INITIALIZED;
    if (assert_lexer_defect_not_raised(ldSelf) == INPUT_READER_FAIL) return INPUT_READER_DEFECT_ALREADY_RAISED;

    ldSelf->uDefectCode = uDefectCode;
    ldSelf->uStartIdx = ldSelf->irReader->uCaret;
    ldSelf->bRaised = 1;
    return INPUT_READER_SUCCESS;
}

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
    *out_pChar = irSelf->pInput[irSelf->uCaret];
    return INPUT_READER_SUCCESS;
}

char advance_next_char(struct input_reader* irSelf, char* out_pChar) {
    if (assert_input_reader_not_initialized(irSelf) == INPUT_READER_SUCCESS) return INPUT_READER_NOT_INITIALIZED;
    if (irSelf->uCaret >= irSelf->uDataLen) return INPUT_READER_OOB;
    
    if (out_pChar != 0) {
        *out_pChar = irSelf->pInput[irSelf->uCaret];
    }
    irSelf->uCaret++;
    return INPUT_READER_SUCCESS;
}

char advance_next_char_predicate(struct input_reader* irSelf, char* out_pChar, READ_PREDICATE_FUNCTION((*fpPredicate)), struct lexer_defect* ldDefect, void* pCtx) {
    char peekChar;
    char ePeek = peek_next_char(irSelf, &peekChar);
    if (ePeek == INPUT_READER_OOB) return INPUT_READER_REJECT;
    if (ePeek != INPUT_READER_SUCCESS) return ePeek;

    char result = fpPredicate(peekChar, ldDefect, pCtx);
    if (result == INPUT_READER_SUCCESS) {
        char eAdvance = advance_next_char(irSelf, out_pChar);
        if (eAdvance != INPUT_READER_SUCCESS) return eAdvance;
    }
    return result;
}

char allocate_and_read_while(struct input_reader* irSelf, char** ppBuff, unsigned int* iBytesRead, READ_PREDICATE_FUNCTION((*fpPredicate)), struct lexer_defect* ldDefect, void* pCtx) {
    unsigned int buffSize = 32;
    *ppBuff = (char*)calloc(buffSize, sizeof(char));
    if (*ppBuff == 0) return INPUT_READER_FAIL;
    unsigned int i = 0;
    char eAdvance = 0;
    while ((eAdvance = advance_next_char_predicate(irSelf, &(*ppBuff)[i], fpPredicate, ldDefect, pCtx)) == INPUT_READER_SUCCESS) {
        i++;
        if (i >= buffSize) {
            buffSize *= 2;
            *ppBuff = (char*)realloc(*ppBuff, buffSize);
            if (*ppBuff == 0) return INPUT_READER_FAIL;
        }
    }
    if (eAdvance == INPUT_READER_REJECT) {
        if (i == 0) { // no input was read
            free(*ppBuff);
            return INPUT_READER_REJECT;
        }
        
        *ppBuff = (char*)realloc(*ppBuff, i + 1);
        if (*ppBuff == 0) return INPUT_READER_FAIL;
        (*ppBuff)[i] = '\0';
        *iBytesRead = i;
        return INPUT_READER_SUCCESS;
    }

    return eAdvance;
}

char allocate_and_read_many_chars(struct input_reader* irSelf, char** out_pChar, char* pChars, int iNumChars) {
    if (assert_input_reader_not_initialized(irSelf) == INPUT_READER_SUCCESS) return INPUT_READER_NOT_INITIALIZED;
    if (irSelf->uCaret >= irSelf->uDataLen - (iNumChars - 1)) return INPUT_READER_REJECT;

    const char* base = &irSelf->pInput[irSelf->uCaret];
    if (memcmp(base, pChars, iNumChars) == 0) {
        *out_pChar = (char*)malloc(iNumChars + 1);
        if (*out_pChar == 0) return INPUT_READER_FAIL;
        irSelf->uCaret += iNumChars;
        memcpy(*out_pChar, base, iNumChars);
        (*out_pChar)[iNumChars] = '\0';
        return INPUT_READER_SUCCESS;
    }
    return INPUT_READER_REJECT;
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
    if (fiirRange != 0) {
        fiirRange->uStartIdx = rsSelf->uStartCaret;
        fiirRange->uEndIdx = rsSelf->irParent->uCaret;
    }
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
    tSelf->pContent = content;
    return INPUT_READER_SUCCESS;
}

char get_tokens(const char* pFileName, const char* pInput, struct vector* defect_list, struct vector* token_list) {
    struct input_reader reader = create_input_reader();
    init_input_reader(&reader, pFileName, pInput);

    struct read_session session1 = create_read_session();
    init_read_session(&session1, &reader);
    open_read_session(&session1);

    int remainingBytes;
    while (get_remaining_bytes(&reader, &remainingBytes) == INPUT_READER_SUCCESS && remainingBytes > 0) {
        struct token token = create_token();
        struct lexer_defect defect = create_lexer_defect();
        char eDefect = init_lexer_defect(&defect, &reader);
        if (eDefect != INPUT_READER_SUCCESS) return eDefect;
        char eReadNextToken = read_token_next(&reader, &defect, &token);
        if (eReadNextToken == INPUT_READER_DEFECT) {
            if (assert_lexer_defect_not_raised(&defect) == INPUT_READER_SUCCESS) return INPUT_READER_EXPECTED_DEFECT_NOT_RAISED;
            vector_append(defect_list, &defect);
            continue;
        }
        if (eReadNextToken == INPUT_READER_REJECT) continue;
        if (eReadNextToken != INPUT_READER_SUCCESS) return eReadNextToken;
        vector_append(token_list, &token);
    }

    for (unsigned int i = 0; i < defect_list->uLength; i++) {
        struct lexer_defect* defect;
        char eGetDefect = vector_at_ref(defect_list, i, (void**)&defect);
        if (eGetDefect != INPUT_READER_SUCCESS) return eGetDefect;

        printf("Lexer defect (%i) @ %i: ", defect->uDefectCode, defect->uStartIdx);
        switch (defect->uDefectCode) {
        case LEXER_DEFECT_NIL:
            printf("Unknown defect\n");
            break;
        case LEXER_DEFECT_UNEXPECTED_NEWLINE:
            printf("Unexpected newline in string\n");
            break;
        }
    }

    for (unsigned int i = 0; i < token_list->uLength; i++) {
        struct token* token;
        char eGetToken = vector_at_ref(token_list, i, (void**)&token);
        if (eGetToken != INPUT_READER_SUCCESS) return eGetToken;

        printf("Token (%i): %s\n", token->iKind, token->pContent);
    }

    return INPUT_READER_SUCCESS;
}

READ_TOKEN_FUNCTION(next) {
    T_READ_TOKEN_FUNCTION((*token_readers[])) =
        { &read_token_ident, &read_token_number, &read_token_string,
        &read_token_par_open, &read_token_par_close, &read_token_operator,
        &read_token_separator, &read_token_reference };
    int numReads = sizeof(token_readers) / sizeof(token_readers[0]);

    for (int i = 0; i < numReads; i++) {
        char e1 = token_readers[i](irReader, ldDefect, out_tToken);
        if (e1 == INPUT_READER_SUCCESS) return INPUT_READER_SUCCESS;
        if (e1 != INPUT_READER_REJECT) return e1;
    }

    char tmp;
    advance_next_char(irReader, &tmp);
    return INPUT_READER_REJECT;
}

READ_PREDICATE_FUNCTION(is_digit) {
    return c >= '0' && c <= '9' ? INPUT_READER_SUCCESS : INPUT_READER_REJECT;
}

READ_PREDICATE_FUNCTION(is_valid_identifier_char) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || is_digit(c, ldDefect, pCtx) == INPUT_READER_SUCCESS
        ? INPUT_READER_SUCCESS : INPUT_READER_REJECT; 
}

READ_PREDICATE_FUNCTION(is_quote) {
    return c == '"' ? INPUT_READER_SUCCESS : INPUT_READER_REJECT;
}

READ_PREDICATE_FUNCTION(is_closing_quote) {
    return c == '"' ? INPUT_READER_SUCCESS : INPUT_READER_REJECT;
}

READ_PREDICATE_FUNCTION(is_non_closing_quote) {
    char* escapeParity = (char*)pCtx;
    switch (c) {
    case '\\':
        *escapeParity = !*escapeParity;
        return INPUT_READER_SUCCESS;
    case '"':
        if (*escapeParity == 0) return INPUT_READER_REJECT;
        *escapeParity = 0;
        return INPUT_READER_SUCCESS;
    case '\n':;
        char eRaise = raise_lexer_defect(ldDefect, LEXER_DEFECT_UNEXPECTED_NEWLINE);
        if (eRaise != INPUT_READER_SUCCESS) return eRaise;
        return INPUT_READER_DEFECT;
    }
    return INPUT_READER_SUCCESS;
}

char read_token_enum(struct input_reader* irReader, struct lexer_defect* ldDefect, struct token* out_tToken, char iTokenKind, const char** ppEnum, unsigned int uNumEnum){
    struct read_session wholeEnumSession = create_read_session();
    char eInit = init_read_session(&wholeEnumSession, irReader);
    if (eInit != INPUT_READER_SUCCESS) return eInit;
    
    char eOpen = open_read_session(&wholeEnumSession);
    if (eOpen != INPUT_READER_SUCCESS) return eOpen;

    char enumString;
    for (int i = 0; i < uNumEnum; i++) {
        const char* chars = ppEnum[i];
        char* buff = 0;
        char eReadChars = allocate_and_read_many_chars(irReader, &buff, (char*)chars, strlen(chars));
        if (eReadChars == INPUT_READER_REJECT) continue;
        if (eReadChars != INPUT_READER_SUCCESS) return eReadChars;
        if (buff == 0) {
            close_and_retreat_read_session(&wholeEnumSession);
            return INPUT_READER_FAIL;
        }

        struct file_input_idx_range range = create_file_input_idx_range();
        char eClose = close_read_session(&wholeEnumSession, &range);
        if (eClose != INPUT_READER_SUCCESS) {
            free(buff);
            close_and_retreat_read_session(&wholeEnumSession);
            return INPUT_READER_FAIL;
        }
        char eSet = set_token(out_tToken, iTokenKind, range, buff);
        if (eSet != INPUT_READER_SUCCESS) {
            free(buff);
            return eSet;
        }

        return INPUT_READER_SUCCESS;
    }
    return INPUT_READER_REJECT;
}

READ_TOKEN_FUNCTION(ident) {
    struct read_session wholeIdentifierSession = create_read_session();
    char eInit = init_read_session(&wholeIdentifierSession, irReader);
    if (eInit != INPUT_READER_SUCCESS) return eInit;
    
    char eOpen = open_read_session(&wholeIdentifierSession);
    if (eOpen != INPUT_READER_SUCCESS) return eOpen;

    char ePeekFirst;
    char ePeek = peek_next_char(irReader, &ePeekFirst);
    if (ePeek != INPUT_READER_SUCCESS) {
        close_and_retreat_read_session(&wholeIdentifierSession);
        return ePeek;
    }
    if (is_digit(ePeekFirst, ldDefect, 0) == INPUT_READER_SUCCESS) {
        close_and_retreat_read_session(&wholeIdentifierSession);
        return INPUT_READER_REJECT;
    }

    char* buff = 0;
    unsigned int bytesRead = 0;
    char eReadIdent = allocate_and_read_while(irReader, &buff, &bytesRead, &is_valid_identifier_char, ldDefect, 0);
    if (eReadIdent != INPUT_READER_SUCCESS) {
        close_and_retreat_read_session(&wholeIdentifierSession);
        return eReadIdent;
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

char read_token_number_decimal(struct input_reader* irReader, struct lexer_defect* ldDefect, char* pNumberStrBuff, unsigned int iNumberBytesRead, struct file_input_idx_range* fiirDecimalRange) {
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
    char eReadDecimal = allocate_and_read_while(irReader, &buffDecimal, &bytesReadDecimal, &is_digit, ldDefect, 0);
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

READ_TOKEN_FUNCTION(number) {
    struct read_session wholeNumberSession = create_read_session();
    char eInit = init_read_session(&wholeNumberSession, irReader);
    if (eInit != INPUT_READER_SUCCESS) return eInit;

    char eOpen = open_read_session(&wholeNumberSession);
    if (eOpen != INPUT_READER_SUCCESS) return eOpen;

    char* buff = 0;
    unsigned int bytesRead = 0;
    char eReadNumber = allocate_and_read_while(irReader, &buff, &bytesRead, &is_digit, ldDefect, 0);
    if (eReadNumber != INPUT_READER_SUCCESS) {
        close_and_retreat_read_session(&wholeNumberSession);
        return eReadNumber;
    }

    struct file_input_idx_range decimalRange = create_file_input_idx_range();
    char eReadDecimal = read_token_number_decimal(irReader, ldDefect, buff, bytesRead, &decimalRange);
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

    return INPUT_READER_SUCCESS;
}

READ_TOKEN_FUNCTION(string) {
    struct read_session wholeStringSession = create_read_session();
    char eInit = init_read_session(&wholeStringSession, irReader);
    if (eInit != INPUT_READER_SUCCESS) return eInit;
    
    char eOpen = open_read_session(&wholeStringSession);
    if (eOpen != INPUT_READER_SUCCESS) return eOpen;

    char ePeek = advance_next_char_predicate(irReader, 0, &is_quote, ldDefect, 0);
    if (ePeek != INPUT_READER_SUCCESS) {
        close_and_retreat_read_session(&wholeStringSession);
        return ePeek;
    }

    char* buff = 0;
    unsigned int bytesRead = 0;
    char backslashParity = 0;
    char eReadIdent = allocate_and_read_while(irReader, &buff, &bytesRead, &is_non_closing_quote, ldDefect, &backslashParity);
    if (eReadIdent != INPUT_READER_SUCCESS && eReadIdent != INPUT_READER_REJECT) {
        if (eReadIdent == INPUT_READER_DEFECT) {
            close_read_session(&wholeStringSession, 0); /* safely skip string if it has lexer defect */
        } else {
            close_and_retreat_read_session(&wholeStringSession);
        }
        return eReadIdent;
    }
    char ePeek2 = advance_next_char_predicate(irReader, 0, &is_closing_quote, ldDefect, 0);
    if (ePeek2 != INPUT_READER_SUCCESS) {
        close_and_retreat_read_session(&wholeStringSession);
        return ePeek2;
    }
    if (eReadIdent == INPUT_READER_REJECT) {
        buff = (char*)malloc(1);
        if (buff == 0) {
            close_and_retreat_read_session(&wholeStringSession);
            return INPUT_READER_FAIL;
        }
        buff[0] = '\0';
    } else if (eReadIdent != INPUT_READER_SUCCESS) {
        close_and_retreat_read_session(&wholeStringSession);
        return eReadIdent;
    }

    struct file_input_idx_range range = create_file_input_idx_range();
    char eClose = close_read_session(&wholeStringSession, &range);
    if (eClose != INPUT_READER_SUCCESS) {
        free(buff);
        close_and_retreat_read_session(&wholeStringSession);
        return INPUT_READER_FAIL;
    }

    char eSet = set_token(out_tToken, TOKEN_KIND_STR, range, buff);
    if (eSet != INPUT_READER_SUCCESS) return eSet;

    return INPUT_READER_SUCCESS;
}

READ_TOKEN_FUNCTION(par_open) {
    const char* parenthesisSet[] = { "(", "{", "[" };
    return read_token_enum(irReader, ldDefect, out_tToken, TOKEN_KIND_PAR_OPEN, parenthesisSet, sizeof(parenthesisSet) / sizeof(const char*));
}

READ_TOKEN_FUNCTION(par_close) {
    const char* parenthesisSet[] = { ")", "}", "]" };
    return read_token_enum(irReader, ldDefect, out_tToken, TOKEN_KIND_PAR_CLOSE, parenthesisSet, sizeof(parenthesisSet) / sizeof(const char*));
}

READ_TOKEN_FUNCTION(operator) {
    const char* operatorSet[] = { ".", "->", "==", "=", ">=", "<=", "+", "-", "*", "/", "%", "&&", "||", "&" };
    return read_token_enum(irReader, ldDefect, out_tToken, TOKEN_KIND_OPERATOR, operatorSet, sizeof(operatorSet) / sizeof(const char*));
}

READ_TOKEN_FUNCTION(separator) {
    const char* separatorSet[] = { ",", ";" };
    return read_token_enum(irReader, ldDefect, out_tToken, TOKEN_KIND_SEPARATOR, separatorSet, sizeof(separatorSet) / sizeof(const char*));
}

READ_TOKEN_FUNCTION(reference) {
    const char* referenceSet[] = { "@" };
    return read_token_enum(irReader, ldDefect, out_tToken, TOKEN_KIND_REFERENCE, referenceSet, sizeof(referenceSet) / sizeof(const char*));
}