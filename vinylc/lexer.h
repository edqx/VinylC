#ifndef LEXER_H
#define LEXER_H

#include "vector.h"

#define INPUT_READER_SUCCESS (char)0
#define INPUT_READER_FAIL (char)1
#define INPUT_READER_ALREADY_INITIALIZED (char)2
#define INPUT_READER_NOT_INITIALIZED (char)3
#define INPUT_READER_OOB (char)4
#define INPUT_READER_REJECT (char)5
#define INPUT_READER_DEFECT (char)6
#define INPUT_READER_EXPECTED_DEFECT_NOT_RAISED (char)7
#define INPUT_READER_DEFECT_ALREADY_RAISED (char)8

#define LEXER_DEFECT_NIL (char)0
#define LEXER_DEFECT_UNEXPECTED_NEWLINE (char)1

struct input_reader {
    const char* pFileName;
    const char* pInput;
    unsigned int uDataLen;
    unsigned int uCaret;
};

struct lexer_defect {
    struct input_reader* irReader;
    char bRaised;
    unsigned int uStartIdx;
    unsigned int uDefectCode;
};

struct read_session {
    struct input_reader* irParent;
    unsigned int uStartCaret;
};

struct file_input_idx_range {
    const char* pFileName;
    unsigned int uStartIdx;
    unsigned int uEndIdx;
};

struct input_reader create_input_reader();
char assert_input_reader_not_initialized(struct input_reader* irSelf);
char init_input_reader(struct input_reader* irSelf, const char* pFileName, const char* pInput);
char get_remaining_bytes(struct input_reader* irSelf, unsigned int* out_iRemainingBytes);
char peek_next_char(struct input_reader* irSelf, char* out_pChar);
char advance_next_char(struct input_reader* irSelf, char* out_pChar);

#define READ_PREDICATE_FUNCTION(NAME) char NAME(char c, struct lexer_defect* ldDefect, void* pCtx)

char advance_next_char_predicate(struct input_reader* irSelf, char* out_pChar, READ_PREDICATE_FUNCTION((*fpPredicate)), struct lexer_defect* ldDefect, void* pCtx);
char allocate_and_read_while(struct input_reader* irSelf, char** ppBuff, unsigned int* iBytesRead, READ_PREDICATE_FUNCTION((*fpPredicate)), struct lexer_defect* ldDefect, void* pCtx);
char allocate_and_read_many_chars(struct input_reader* irSelf, char** out_pChar, char* pChars, int iNumChars);

struct lexer_defect create_lexer_defect();
char assert_lexer_defect_not_initialized(struct lexer_defect* ldSelf);
char init_lexer_defect(struct lexer_defect* ldSelf, struct input_reader* irReader);
char assert_lexer_defect_not_raised(struct lexer_defect* ldSelf);
char raise_lexer_defect(struct lexer_defect* ldSelf, unsigned int uDefectCode);

struct read_session create_read_session();
struct file_input_idx_range create_file_input_idx_range();
struct file_input_idx_range contain_file_input_idx_range(struct file_input_idx_range a, struct file_input_idx_range b);
char assert_read_session_not_initialized(struct read_session* rsSelf);
char init_read_session(struct read_session* rsSelf, struct input_reader* irParent);
char open_read_session(struct read_session* rsSelf);
char close_read_session(struct read_session* rsSelf, struct file_input_idx_range* fiirRange);
char close_and_retreat_read_session(struct read_session* rsSelf);

#define TOKEN_KIND_EMPTY (char)0
#define TOKEN_KIND_EOF (char)1
#define TOKEN_KIND_IDENT (char)2
#define TOKEN_KIND_STR (char)3
#define TOKEN_KIND_NUMBER (char)4
#define TOKEN_KIND_PAR_OPEN (char)5
#define TOKEN_KIND_PAR_CLOSE (char)6
#define TOKEN_KIND_OPERATOR (char)7
#define TOKEN_KIND_SEPARATOR (char)8

struct token {
    char iKind;
    struct file_input_idx_range fiirFileRange;
    const char* pContent;
};

READ_PREDICATE_FUNCTION(is_digit);
READ_PREDICATE_FUNCTION(is_valid_identifier_char);
READ_PREDICATE_FUNCTION(is_quote);
READ_PREDICATE_FUNCTION(is_closing_quote);
READ_PREDICATE_FUNCTION(is_non_closing_quote);

struct token create_token();
char set_token(struct token* tSelf, char iKind, struct file_input_idx_range fiirFileRange, const char* content);
char get_tokens(const char* pFileName, const char* pInput, struct vector* defect_list, struct vector* token_list);

#define T_READ_TOKEN_FUNCTION(NAME) char NAME(struct input_reader* irReader, struct lexer_defect* ldDefect, struct token* out_tToken)
#define READ_TOKEN_FUNCTION(NAME) T_READ_TOKEN_FUNCTION(read_token_##NAME)
char read_token_enum(struct input_reader* irReader, struct lexer_defect* ldDefect, struct token* out_tToken, char iTokenKind, const char** ppEnum, unsigned int uNumEnum);
READ_TOKEN_FUNCTION(next);
READ_TOKEN_FUNCTION(ident);
char read_token_number_decimal(struct input_reader* irReader, struct lexer_defect* ldDefect, char* pNumberStrBuff, unsigned int iNumberBytesRead, struct file_input_idx_range* fiirDecimalRange);
READ_TOKEN_FUNCTION(number);
READ_TOKEN_FUNCTION(string);
READ_TOKEN_FUNCTION(par_open);
READ_TOKEN_FUNCTION(par_close);
READ_TOKEN_FUNCTION(operator);
READ_TOKEN_FUNCTION(separator);

#endif // LEXER_H