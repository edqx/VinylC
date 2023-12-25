#define INPUT_READER_SUCCESS '\0'
#define INPUT_READER_FAIL '\1'
#define INPUT_READER_ALREADY_INITIALIZED '\2'
#define INPUT_READER_NOT_INITIALIZED '\3'
#define INPUT_READER_OOB '\4'
#define INPUT_READER_REJECT '\5'

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
char advance_next_char_predicate(struct input_reader* irSelf, char* out_pChar, char(*fpPredicate)(char iNext));
char allocate_and_read_while(struct input_reader* irSelf, char** ppBuff, unsigned int* iBytesRead, char(*fpPredicate)(char iNext));

struct read_session create_read_session();
struct file_input_idx_range create_file_input_idx_range();
struct file_input_idx_range contain_file_input_idx_range(struct file_input_idx_range a, struct file_input_idx_range b);
char assert_read_session_not_initialized(struct read_session* rsSelf);
char init_read_session(struct read_session* rsSelf, struct input_reader* irParent);
char open_read_session(struct read_session* rsSelf);
char close_read_session(struct read_session* rsSelf, struct file_input_idx_range* fiirRange);
char close_and_retreat_read_session(struct read_session* rsSelf);

#define TOKEN_KIND_EMPTY '\0'
#define TOKEN_KIND_IDENT '\1'
#define TOKEN_KIND_STR '\2'
#define TOKEN_KIND_NUMBER '\3'
#define TOKEN_KIND_PAR_OPEN '\4'
#define TOKEN_KIND_PAR_CLOSE '\5'
#define TOKEN_KIND_ACCESSOR '\6'

struct token {
    char iKind;
    struct file_input_idx_range fiirFileRange;
    const char* content;
};

struct token create_token();
char set_token(struct token* tSelf, char iKind, struct file_input_idx_range fiirFileRange, const char* content);
char get_tokens(const char* pFileName, const char* pInput);
char read_token_ident(struct input_reader* irReader, struct token* out_tToken);
char read_token_number_decimal(struct input_reader* irReader, char* pNumberStrBuff, unsigned int iNumberBytesRead, struct file_input_idx_range* fiirDecimalRange);
char read_token_number(struct input_reader* irReader, struct token* out_tToken);