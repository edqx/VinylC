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

struct syntax_error {
    short uErrorCode;
    void* pSpecificCtx;
};

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
char get_operator_precedence(struct token* tToken, char bIsUnary);
char allocate_ast_literal_from_token(struct token* tToken, struct ast_literal** out_alLiteral);

struct operator_pending_pop {
    struct token* tOperator;
    char bIsUnary;
};

char eval_stack_pop_operator(struct vector* vEvalStack, struct operator_pending_pop tOperatorPending, struct ast_node** out_anNode);
char pop_greater_precedence(char iPrecedence, struct vector* vOperatorStack, struct vector* vEvalStack);
char build_stmt_list_node(struct token** ptTokens, unsigned int uNumTokens, struct ast_node** out_anStmtListNode);
char build_variable_assignment_node(struct token** ptTokens, unsigned int uNumTokens, struct ast_node* out_anNode);

void print_ast_string(struct ast_elem* anRootElem, int indent);

#endif // AST_H