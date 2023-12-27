#ifndef AST_H
#define AST_H

#include "lexer.h"
#include "vector.h"

#define AST_NODE_SUCCESS (char)0
#define AST_NODE_FAIL (char)1
#define AST_NODE_ALREADY_INITIALIZED (char)2
#define AST_NODE_NOT_INITIALIZED (char)3
#define AST_NODE_NOT_LITERAL_TOKEN (char)4
#define AST_NODE_NOT_OPERATOR_TOKEN (char)5
#define AST_NODE_NOT_EMPTY_NODE (char)6
#define AST_NODE_OOB (char)7

#define AST_NODE_KIND_EMPTY (char)0
#define AST_NODE_KIND_LITERAL (char)1
#define AST_NODE_KIND_STMT_LIST (char)2
#define AST_NODE_KIND_BINARY_OPER (char)3
#define AST_NODE_KIND_UNARY_OPER (char)4

#define AST_LITERAL_KIND_NIL (char)0
#define AST_LITERAL_KIND_STR (char)1
#define AST_LITERAL_KIND_NUM (char)2
#define AST_LITERAL_KIND_IDENT (char)3
#define AST_LITERAL_KIND_OPER (char)4

#define AST_OPERATOR_PRECEDENCE_NIL (char)0
#define AST_OPERATOR_PRECEDENCE_ASSIGN (char)1
#define AST_OPERATOR_PRECEDENCE_LOGIC_OR (char)2
#define AST_OPERATOR_PRECEDENCE_LOGIC_AND (char)3
#define AST_OPERATOR_PRECEDENCE_EQUAL (char)4
#define AST_OPERATOR_PRECEDENCE_COMPARE (char)5
#define AST_OPERATOR_PRECEDENCE_CONCAT (char)6
#define AST_OPERATOR_PRECEDENCE_ADD (char)7
#define AST_OPERATOR_PRECEDENCE_MUL (char)8
#define AST_OPERATOR_PRECEDENCE_UNARY_PREF (char)9
#define AST_OPERATOR_PRECEDENCE_ACCESS (char)10

#define SYNTAX_ERROR_NIL (short)0
#define SYNTAX_ERROR_INVALID_UNARY_OPERATOR (short)1

struct syntax_error {
    short uErrorCode;
    void* pSpecificCtx;
};

struct syntax_error_invalid_unary_operator_context {
    struct token* tToken;
};

#define INSTANCE_SYNTAX_ERROR_CONTEXT(VARNAME, CONTEXT_STRUCT) struct CONTEXT_STRUCT* VARNAME = (struct CONTEXT_STRUCT*)malloc(sizeof(struct CONTEXT_STRUCT))
#define REGISTER_SYNTAX_ERROR(SYNTAX_ERRORS_STORE, VARNAME, ERROR_CODE, CONTEXT_VARNAME) struct syntax_error VARNAME = create_error(ERROR_CODE, CONTEXT_VARNAME); \
    vector_append(SYNTAX_ERRORS_STORE, &VARNAME)

#define SYNTAX_ERROR_PRINT_FUNCTION(ERROR_NAME, CONTEXT_STRUCT) void print_error_##ERROR_NAME(const char* pFileContent, struct CONTEXT_STRUCT* pContext)
#define SYNTAX_ERROR_PRINT(FILE_CONTENT, ERROR_NAME, CONTEXT_STRUCT, ERROR) print_error_##ERROR_NAME(FILE_CONTENT, (struct CONTEXT_STRUCT*)ERROR.pSpecificCtx)

struct syntax_error create_error(short uErrorCode, void* pSpecificContext);
void print_error(const char* pFileContent, struct syntax_error seSyntaxError);
SYNTAX_ERROR_PRINT_FUNCTION(invalid_unary_operator, syntax_error_invalid_unary_operator_context);

struct ast_elem {
    char iKind;
};

struct ast_node {
    char iKind;
    unsigned int uNumSons;
    struct ast_elem** ppSons;
};

struct ast_literal {
    char iKind;
    char iLiteralKind;
    const char* pContent;
};

struct ast_node create_ast_node();
char new_ast_node(struct ast_node** out_anNode);
char assert_ast_node_not_initialized(struct ast_node* anSelf);
char init_ast_node(struct ast_node* anSelf, char uKind, unsigned int uNumSons);
char replace_empty_node(struct ast_node* anSelf, struct ast_elem* anReplacement, unsigned int uSonIdx);

struct ast_literal create_ast_literal();
char new_ast_literal(struct ast_literal** out_alLiteral);
char assert_ast_literal_not_initialized(struct ast_literal* alSelf);
char init_ast_literal(struct ast_literal* alSelf, char iLiteralKind, const char* pContent);
char get_literal_token_kind(struct token* tToken);
char allocate_ast_literal_from_token(struct token* tToken, struct ast_literal** out_alLiteral);

char can_operator_be_unary(struct token* tToken);
char get_operator_precedence(struct token* tToken, char bIsUnary);

struct operator_pending_pop {
    struct token* tOperator;
    char bIsUnary;
};

char eval_stack_pop_operator(struct vector* vEvalStack, struct vector* vSyntaxErrors, struct operator_pending_pop tOperatorPending, struct ast_node** out_anNode);
char pop_greater_precedence(char iPrecedence, struct vector* vOperatorStack, struct vector* vEvalStack, struct vector* vSyntaxErrors);
char build_stmt_list_node(struct token** ptTokens, struct vector* vSyntaxErrors, unsigned int uNumTokens, struct ast_node** out_anStmtListNode);
char build_variable_assignment_node(struct token** ptTokens, unsigned int uNumTokens, struct ast_node* out_anNode);

void print_ast_string(struct ast_elem* anRootElem, int indent);

#endif // AST_H