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
#define AST_NODE_WRONG_NODE_KIND (char)8
#define AST_NODE_INVALID_PARENTHESIS (char)9
#define AST_NODE_STOP (char)10

#define AST_NODE_KIND_EMPTY (char)0
#define AST_NODE_KIND_LITERAL (char)1
#define AST_NODE_KIND_STMT_LIST (char)2
#define AST_NODE_KIND_BINARY_OPER (char)3
#define AST_NODE_KIND_UNARY_OPER (char)4
#define AST_NODE_KIND_VAR_DECL_STMT (char)5
#define AST_NODE_KIND_PAR (char)6

#define AST_LITERAL_KIND_NIL (char)0
#define AST_LITERAL_KIND_STR (char)1
#define AST_LITERAL_KIND_NUM (char)2
#define AST_LITERAL_KIND_IDENT (char)3
#define AST_LITERAL_KIND_OPER (char)4

struct syntax_error {
    short uErrorCode;
    void* pSpecificCtx;
};

#define SYNTAX_ERROR_NIL (short)0
#define SYNTAX_ERROR_INVALID_UNARY_OPERATOR (short)1
#define SYNTAX_ERROR_EXPECTED_OPERATOR (short)2
#define SYNTAX_ERROR_VAR_STMT_EXPECTED_ASSIGNMENT (short)3
#define SYNTAX_ERROR_MISSING_RIGHT_HAND_OPERAND (short)4
#define SYNTAX_ERROR_VAR_STMT_EXPECTED_IDENTIFIER (short)5

struct syntax_error_invalid_unary_operator_context { struct token* tToken; };
struct syntax_error_expected_operator_context { struct token* tToken; };
struct syntax_error_var_stmt_expected_assignment_context { struct token* tVarToken; struct ast_elem* aeOperator; };
struct syntax_error_missing_right_hand_operand_context { struct token* tToken; };
struct syntax_error_var_stmt_expected_identifier_context { struct token* tVarToken; struct ast_elem* aeLeftHandElem; };

#define INSTANCE_SYNTAX_ERROR_CONTEXT(VARNAME, CONTEXT_STRUCT) struct CONTEXT_STRUCT* VARNAME = (struct CONTEXT_STRUCT*)malloc(sizeof(struct CONTEXT_STRUCT))
#define REGISTER_SYNTAX_ERROR(SYNTAX_ERRORS_STORE, VARNAME, ERROR_CODE, CONTEXT_VARNAME) struct syntax_error VARNAME = create_error(ERROR_CODE, CONTEXT_VARNAME);\
    vector_append(SYNTAX_ERRORS_STORE, &VARNAME)

#define SYNTAX_ERROR_PRINT_FUNCTION(ERROR_NAME, CONTEXT_STRUCT) void print_error_##ERROR_NAME(const char* pFileContent, struct CONTEXT_STRUCT* pContext)
#define SYNTAX_ERROR_PRINT(FILE_CONTENT, ERROR_NAME, CONTEXT_STRUCT, ERROR) print_error_##ERROR_NAME(FILE_CONTENT, (struct CONTEXT_STRUCT*)ERROR.pSpecificCtx)

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
    struct token* tToken;
};

struct syntax_error create_error(short uErrorCode, void* pSpecificContext);
void print_error(const char* pFileContent, struct syntax_error seSyntaxError);
void recursive_get_ast_range(struct ast_elem* aeRootElem, struct file_input_idx_range** fiirRange);
SYNTAX_ERROR_PRINT_FUNCTION(invalid_unary_operator, syntax_error_invalid_unary_operator_context);
SYNTAX_ERROR_PRINT_FUNCTION(expected_operator, syntax_error_expected_operator_context);
SYNTAX_ERROR_PRINT_FUNCTION(var_stmt_expected_assignment, syntax_error_var_stmt_expected_assignment_context);
SYNTAX_ERROR_PRINT_FUNCTION(missing_right_hand_operand, syntax_error_missing_right_hand_operand_context);
SYNTAX_ERROR_PRINT_FUNCTION(var_stmt_expected_identifier, syntax_error_var_stmt_expected_identifier_context);

struct ast_node create_ast_node();
char new_ast_node(struct ast_node** out_anNode);
char assert_ast_node_not_initialized(struct ast_node* anSelf);
char init_ast_node(struct ast_node* anSelf, char uKind, unsigned int uNumSons);
char replace_empty_node(struct ast_node* anSelf, struct ast_elem* anReplacement, unsigned int uSonIdx);

struct ast_literal create_ast_literal();
char new_ast_literal(struct ast_literal** out_alLiteral);
char assert_ast_literal_not_initialized(struct ast_literal* alSelf);
char init_ast_literal(struct ast_literal* alSelf, char iLiteralKind, struct token* tToken);
char get_literal_token_kind(struct token* tToken);
char allocate_ast_literal_from_token(struct token* tToken, struct ast_literal** out_alLiteral);

char can_operator_be_unary(struct token* tToken);

#define OPERATOR_PARSE_MODE_NIL (char)0
#define OPERATOR_PARSE_MODE_BINARY (char)1
#define OPERATOR_PARSE_MODE_UNARY (char)2
#define OPERATOR_PARSE_MODE_VAR_STMT (char)3
#define OPERATOR_PARSE_MODE_PROC_STMT (char)4
#define OPERATOR_PARSE_MODE_TYPE_STMT (char)5

#define AST_PRECEDENCE_NIL (char)0
#define AST_PRECEDENCE_STATEMENT (char)1
#define AST_PRECEDENCE_OPERATOR_ASSIGN (char)2
#define AST_PRECEDENCE_OPERATOR_LOGIC_OR (char)3
#define AST_PRECEDENCE_OPERATOR_LOGIC_AND (char)4
#define AST_PRECEDENCE_OPERATOR_EQUAL (char)5
#define AST_PRECEDENCE_OPERATOR_COMPARE (char)6
#define AST_PRECEDENCE_OPERATOR_CONCAT (char)7
#define AST_PRECEDENCE_OPERATOR_ADD (char)8
#define AST_PRECEDENCE_OPERATOR_MUL (char)9
#define AST_PRECEDENCE_OPERATOR_UNARY_PREF (char)10
#define AST_PRECEDENCE_OPERATOR_ACCESS (char)11

char get_operator_precedence(struct token* tToken, char iOperatorParseMode);
char get_keyword_operator_parse_mode(const char* pIdentStr);

struct operator_pending_pop {
    struct token* tToken;
    char iOperatorParseMode;
};

#define AST_ELEM_GET_FUNCTION(NODE_KIND_NAME, SON_NAME, OUT_NAME) char get_##NODE_KIND_NAME##_##SON_NAME(struct ast_elem* aeElem, struct ast_elem** OUT_NAME)
#define AST_ELEM_GET_FUNCTION_IMPL(NODE_KIND, SON_IDX, OUT_NAME) {\
    if (aeElem->iKind != NODE_KIND) return AST_NODE_WRONG_NODE_KIND;\
    if (assert_ast_node_not_initialized((struct ast_node*)aeElem) == AST_NODE_SUCCESS) return AST_NODE_NOT_INITIALIZED;\
    *OUT_NAME = ((struct ast_node*)aeElem)->ppSons[SON_IDX];\
    return AST_NODE_SUCCESS;\
} 

#define AST_ELEM_GET_LITERAL_FUNCTION(NODE_KIND_NAME, SON_NAME, OUT_NAME) char get_##NODE_KIND_NAME##_##SON_NAME(struct ast_elem* aeElem, const char** OUT_NAME)
#define AST_ELEM_GET_LITERAL_FUNCTION_IMPL(NODE_KIND, SON_IDX, OUT_NAME) {\
    if (aeElem->iKind != NODE_KIND) return AST_NODE_WRONG_NODE_KIND;\
    if (assert_ast_node_not_initialized((struct ast_node*)aeElem) == AST_NODE_SUCCESS) return AST_NODE_NOT_INITIALIZED;\
    *OUT_NAME = ((struct ast_literal*)(((struct ast_node*)aeElem)->ppSons[SON_IDX]))->tToken->pContent;\
    return AST_NODE_SUCCESS;\
} 

AST_ELEM_GET_LITERAL_FUNCTION(binary_operator, operator, out_pOperator);
AST_ELEM_GET_FUNCTION(binary_operator, left_operand, out_aeLeftOperand);
AST_ELEM_GET_FUNCTION(binary_operator, right_operand, out_aeRightOperand);

AST_ELEM_GET_LITERAL_FUNCTION(unary_operator, operator, out_pOperator);
AST_ELEM_GET_FUNCTION(unary_operator, left_operand, out_aeOperand);

AST_ELEM_GET_LITERAL_FUNCTION(var_decl_stmt, var_name, out_pVarName);
AST_ELEM_GET_FUNCTION(var_decl_stmt, var_initializer, out_aeInitializer);

char get_matching_close_parenthesis(char cOpenPar);

char eval_stack_pop_operator(struct vector* vEvalStack, struct vector* vSyntaxErrors, struct token* tOperatorToken, char bIsUnary, struct ast_node** out_anNode);
char eval_stack_pop_var_stmt(struct vector* vEvalStack, struct vector* vSyntaxErrors, struct token* tVarToken, struct ast_node** out_anNode);
char pop_greater_precedence(char iPrecedence, struct vector* vOperatorStack, struct vector* vEvalStack, struct vector* vSyntaxErrors);

#define CONTINUE_AST_PREDICATE_FUNCTION(NAME) char NAME(struct token* pToken,struct vector* vSyntaxErrors, void* pCtx)

CONTINUE_AST_PREDICATE_FUNCTION(is_eof_token);
CONTINUE_AST_PREDICATE_FUNCTION(is_close_parenthesis);

char flush_to_expression_list(struct vector* vExpressionList, struct vector* vOperatorStack, struct vector* vEvalStack);
char build_expression_list(struct token*** pptToken, struct vector* vSyntaxErrors, CONTINUE_AST_PREDICATE_FUNCTION((*fpContinuePredicate)), void *pCtx, struct vector* out_vExpressionList);
char build_stmt_list_node(struct token** ptToken, struct vector* vSyntaxErrors, struct ast_node** out_anStmtListNode);

void print_ast_string(struct ast_elem* anRootElem, int indent);

#endif // AST_H