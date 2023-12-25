#define INPUT_READER_SUCCESS (char)0
#define INPUT_READER_FAIL (char)1
#define INPUT_READER_ALREADY_INITIALIZED (char)2
#define INPUT_READER_NOT_INITIALIZED (char)3
#define INPUT_READER_OOB (char)4
#define INPUT_READER_REJECT (char)5
#define INPUT_READER_UNEXPECTED_END (char)6

struct input_reader {
    const char* pFileName;
    const char* pInput;
    unsigned int uDataLen;
    unsigned int uCaret;
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

#define READ_PREDICATE_FUNCTION(NAME) char NAME(char c, void* pCtx)
char advance_next_char_predicate(struct input_reader* irSelf, char* out_pChar, char(*fpPredicate)(char iNext, void* pCtx), void* pCtx);
char allocate_and_read_while(struct input_reader* irSelf, char** ppBuff, unsigned int* iBytesRead, char(*fpPredicate)(char iNext, void* pCtx), void* pCtx);

struct read_session create_read_session();
struct file_input_idx_range create_file_input_idx_range();
struct file_input_idx_range contain_file_input_idx_range(struct file_input_idx_range a, struct file_input_idx_range b);
char assert_read_session_not_initialized(struct read_session* rsSelf);
char init_read_session(struct read_session* rsSelf, struct input_reader* irParent);
char open_read_session(struct read_session* rsSelf);
char close_read_session(struct read_session* rsSelf, struct file_input_idx_range* fiirRange);
char close_and_retreat_read_session(struct read_session* rsSelf);

#define TOKEN_KIND_EMPTY (char)0
#define TOKEN_KIND_IDENT (char)1
#define TOKEN_KIND_STR (char)2
#define TOKEN_KIND_NUMBER (char)3
#define TOKEN_KIND_PAR_OPEN (char)4
#define TOKEN_KIND_PAR_CLOSE (char)5
#define TOKEN_KIND_ACCESSOR (char)6
#define TOKEN_KIND_ASSIGNMENT (char)7
#define TOKEN_KIND_OPERATOR (char)8
#define TOKEN_KIND_SPLIT (char) 9

struct token {
    char iKind;
    struct file_input_idx_range fiirFileRange;
    const char* content;
};

READ_PREDICATE_FUNCTION(is_digit);
READ_PREDICATE_FUNCTION(is_valid_identifier_char);
READ_PREDICATE_FUNCTION(is_quote);
READ_PREDICATE_FUNCTION(is_closing_quote);
READ_PREDICATE_FUNCTION(is_non_closing_quote);
READ_PREDICATE_FUNCTION(is_open_parenthesis);
READ_PREDICATE_FUNCTION(is_close_parenthesis);

struct token create_token();
char set_token(struct token* tSelf, char iKind, struct file_input_idx_range fiirFileRange, const char* content);
char get_tokens(const char* pFileName, const char* pInput);
char read_next_token(struct input_reader* irReader, struct token* out_tToken);
char read_token_ident(struct input_reader* irReader, struct token* out_tToken);
char read_token_number_decimal(struct input_reader* irReader, char* pNumberStrBuff, unsigned int iNumberBytesRead, struct file_input_idx_range* fiirDecimalRange);
char read_token_number(struct input_reader* irReader, struct token* out_tToken);
char read_token_string(struct input_reader* irReader, struct token* out_tToken);
char read_token_par_open(struct input_reader* irReader, struct token* out_tToken);
char read_token_par_close(struct input_reader* irReader, struct token* out_tToken);