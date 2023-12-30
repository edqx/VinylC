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
#define AST_NODE_UNDEFINED_FUNCTION_CALL (char)11

#define AST_NODE_KIND_EMPTY (char)0
#define AST_NODE_KIND_LITERAL (char)1
#define AST_NODE_KIND_STMT_LIST (char)2
#define AST_NODE_KIND_BINARY_OPER (char)3
#define AST_NODE_KIND_UNARY_OPER (char)4
#define AST_NODE_KIND_VAR_DECL_STMT (char)5
#define AST_NODE_KIND_PAR (char)6
#define AST_NODE_KIND_BLOCK (char)7
#define AST_NODE_KIND_TUPLE (char)8
#define AST_NODE_KIND_CALL (char)9
#define AST_NODE_KIND_FUNCTION_DECL_STMT (char)10
#define AST_NODE_KIND_RETURN_STMT (char)11
#define AST_NODE_KIND_IF_STMT (char)12
#define AST_NODE_KIND_ELSE_STMT (char)13

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
#define SYNTAX_ERROR_INVALID_CLOSE_PARENTHESIS (short)6
#define SYNTAX_ERROR_UNMATCHED_CLOSE_PARENTHESIS (short)7
#define SYNTAX_ERROR_UNMATCHED_OPEN_PARENTHESIS (short)8
#define SYNTAX_ERROR_MISSING_FUNCTION_IMPL (short)9
#define SYNTAX_ERROR_MISSING_FUNCTION_DECL (short)10
#define SYNTAX_ERROR_INVALID_FUNCTION_DECL (short)11
#define SYNTAX_ERROR_INVALID_FUNCTION_NAME (short)12
#define SYNTAX_ERROR_MISSING_IF_CONDITION (short)13
#define SYNTAX_ERROR_IF_CONDITION_NOT_PARENTHESIZED (short)14
#define SYNTAX_ERROR_MISSING_IF_BODY (short)15

struct syntax_error_invalid_unary_operator_context { struct token* tToken; };
struct syntax_error_expected_operator_context { struct token* tToken; };
struct syntax_error_var_stmt_expected_assignment_context { struct token* tVarToken; struct ast_elem* aeOperator; };
struct syntax_error_missing_right_hand_operand_context { struct token* tToken; };
struct syntax_error_var_stmt_expected_identifier_context { struct token* tVarToken; struct ast_elem* aeLeftHandElem; };
struct syntax_error_invalid_close_parenthesis_context { struct token* tOpenParenthesis; struct token* tCloseParenthesis; };
struct syntax_error_unmatched_close_parenthesis_context { struct token* tCloseParenthesis; };
struct syntax_error_unmatched_open_parenthesis_context { struct token* tOpenParenthesis; };
struct syntax_error_missing_function_impl_context { struct token* tFunctionToken; struct ast_elem* aeFunctionCall; struct ast_literal* alFunctionName; };
struct syntax_error_missing_function_decl_context { struct token* tFunctionToken; };
struct syntax_error_invalid_function_decl_context { struct token* tFunctionToken; struct ast_elem* aeFunctionDecl; };
struct syntax_error_invalid_function_name_context { struct token* tFunctionToken; struct ast_elem* aeFunctionRef; };
struct syntax_error_missing_if_condition_context { struct token* tIfToken; };
struct syntax_error_if_condition_not_parenthesized_context { struct token* tIfToken; struct ast_elem* aeIfCondition; };
struct syntax_error_missing_if_body_context { struct token* tIfToken; struct ast_elem* aeIfCondition; };

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
    unsigned int uNumElements;
    struct ast_elem** ppElements;
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
SYNTAX_ERROR_PRINT_FUNCTION(invalid_close_parenthesis, syntax_error_invalid_close_parenthesis_context);
SYNTAX_ERROR_PRINT_FUNCTION(unmatched_close_parenthesis, syntax_error_unmatched_close_parenthesis_context);
SYNTAX_ERROR_PRINT_FUNCTION(unmatched_open_parenthesis, syntax_error_unmatched_open_parenthesis_context);
SYNTAX_ERROR_PRINT_FUNCTION(missing_function_impl, syntax_error_missing_function_impl_context);
SYNTAX_ERROR_PRINT_FUNCTION(missing_function_decl, syntax_error_missing_function_decl_context);
SYNTAX_ERROR_PRINT_FUNCTION(invalid_function_decl, syntax_error_invalid_function_decl_context);
SYNTAX_ERROR_PRINT_FUNCTION(invalid_function_name, syntax_error_invalid_function_name_context);
SYNTAX_ERROR_PRINT_FUNCTION(missing_if_condition, syntax_error_missing_if_condition_context);
SYNTAX_ERROR_PRINT_FUNCTION(if_condition_not_parenthesized, syntax_error_if_condition_not_parenthesized_context);
SYNTAX_ERROR_PRINT_FUNCTION(missing_if_body, syntax_error_missing_if_body_context);

struct ast_node create_ast_node();
char new_ast_node(struct ast_node** out_anNode);
char assert_ast_node_not_initialized(struct ast_node* anSelf);
char init_ast_node(struct ast_node* anSelf, char uKind, unsigned int uNumElements);
char replace_empty_node(struct ast_node* anSelf, struct ast_elem* anReplacement, unsigned int uElementIdx);

struct ast_literal create_ast_literal();
char new_ast_literal(struct ast_literal** out_alLiteral);
char assert_ast_literal_not_initialized(struct ast_literal* alSelf);
char init_ast_literal(struct ast_literal* alSelf, char iLiteralKind, struct token* tToken);
char get_literal_token_kind(struct token* tToken);
char allocate_ast_literal_from_token(struct token* tToken, struct ast_literal** out_alLiteral);

char can_operator_be_unary_pref(struct token* tToken);
char can_operator_be_unary_suff(struct token* tToken);

#define OPERATOR_PARSE_MODE_NIL (char)0
#define OPERATOR_PARSE_MODE_BINARY (char)1
#define OPERATOR_PARSE_MODE_UNARY_PREF (char)2
#define OPERATOR_PARSE_MODE_UNARY_SUFF (char)3
#define OPERATOR_PARSE_MODE_STANDALONE (char)4
#define OPERATOR_PARSE_MODE_VAR_STMT (char)5
#define OPERATOR_PARSE_MODE_FUNCTION_STMT (char)6
#define OPERATOR_PARSE_MODE_TYPE_STMT (char)7
#define OPERATOR_PARSE_MODE_RETURN_STMT (char)8
#define OPERATOR_PARSE_MODE_IF_STMT (char)9
#define OPERATOR_PARSE_MODE_ELSE_STMT (char)10

#define AST_PRECEDENCE_NIL (char)0
#define AST_PRECEDENCE_STATEMENT_RETURN (char)1
#define AST_PRECEDENCE_STATEMENT (char)2
#define AST_PRECEDENCE_STATEMENT_ELSE (char)3
#define AST_PRECEDENCE_OPERATOR_ASSIGN (char)4
#define AST_PRECEDENCE_OPERATOR_LOGIC_OR (char)5
#define AST_PRECEDENCE_OPERATOR_LOGIC_AND (char)6
#define AST_PRECEDENCE_OPERATOR_EQUAL (char)7
#define AST_PRECEDENCE_OPERATOR_COMPARE (char)8
#define AST_PRECEDENCE_OPERATOR_CONCAT (char)9
#define AST_PRECEDENCE_OPERATOR_ADD (char)10
#define AST_PRECEDENCE_OPERATOR_MUL (char)11
#define AST_PRECEDENCE_OPERATOR_UNARY_SUFF (char)12
#define AST_PRECEDENCE_OPERATOR_UNARY_PREF (char)13
#define AST_PRECEDENCE_OPERATOR_ACCESS (char)14

char get_operator_precedence(struct token* tToken, char iOperatorParseMode);
char get_keyword_operator_parse_mode(const char* pIdentStr);

#define AST_ELEM_GET_FUNCTION(NODE_KIND_NAME, ELEMENT_NAME) char get_##NODE_KIND_NAME##_##ELEMENT_NAME(struct ast_elem* aeElem, struct ast_elem** out_aeElem)
#define AST_ELEM_GET_FUNCTION_IMPL(NODE_KIND, ELEMENT_IDX) {\
    if (aeElem->iKind != NODE_KIND) return AST_NODE_WRONG_NODE_KIND;\
    if (assert_ast_node_not_initialized((struct ast_node*)aeElem) == AST_NODE_SUCCESS) return AST_NODE_NOT_INITIALIZED;\
    *out_aeElem = ((struct ast_node*)aeElem)->ppElements[ELEMENT_IDX];\
    return AST_NODE_SUCCESS;\
} 

#define AST_ELEM_GET_LITERAL_FUNCTION(NODE_KIND_NAME, ELEMENT_NAME) char get_##NODE_KIND_NAME##_##ELEMENT_NAME(struct ast_elem* aeElem, const char** out_alLiteral)
#define AST_ELEM_GET_LITERAL_FUNCTION_IMPL(NODE_KIND, ELEMENT_IDX) {\
    if (aeElem->iKind != NODE_KIND) return AST_NODE_WRONG_NODE_KIND;\
    if (assert_ast_node_not_initialized((struct ast_node*)aeElem) == AST_NODE_SUCCESS) return AST_NODE_NOT_INITIALIZED;\
    *out_alLiteral = ((struct ast_literal*)(((struct ast_node*)aeElem)->ppElements[ELEMENT_IDX]))->tToken->pContent;\
    return AST_NODE_SUCCESS;\
} 

AST_ELEM_GET_LITERAL_FUNCTION(binary_operator, operator);
AST_ELEM_GET_FUNCTION(binary_operator, left_operand);
AST_ELEM_GET_FUNCTION(binary_operator, right_operand);

AST_ELEM_GET_LITERAL_FUNCTION(unary_operator, operator);
AST_ELEM_GET_FUNCTION(unary_operator, left_operand);

AST_ELEM_GET_LITERAL_FUNCTION(var_decl_stmt, var_name);
AST_ELEM_GET_FUNCTION(var_decl_stmt, var_initializer);

AST_ELEM_GET_FUNCTION(call, function_ref);
AST_ELEM_GET_FUNCTION(call, params);

AST_ELEM_GET_FUNCTION(if, condition);
AST_ELEM_GET_FUNCTION(if, block);
AST_ELEM_GET_FUNCTION(if, else_block);

char get_matching_close_parenthesis(char cOpenPar);
char get_parenthesis_node_construction_kind(char cOpenPar);

struct operator_pending_pop {
    struct token* tToken;
    char iOperatorParseMode;
};

struct expression_list_builder {
    struct vector* vOperatorStack;
    struct vector* vEvalStack;
    struct vector* vExpressionList;
    struct vector* vSyntaxErrors;
};

struct expression_list_builder create_expression_list_builder();
char init_expression_list_builder(struct expression_list_builder* elbSelf, struct vector* vSyntaxErrors, struct vector* vExpressionList);
char deinit_expression_list_builder(struct expression_list_builder* elbSelf);

char eval_stack_pop_operator(struct expression_list_builder* elbBuilder, struct token* tOperatorToken, char bIsUnaryPref, char bIsUnarySuff, struct ast_node** out_anNode);
char eval_stack_pop_var_stmt(struct expression_list_builder* elbBuilder, struct token* tVarToken, struct ast_node** out_anNode);
char eval_stack_pop_function_decl(struct expression_list_builder* elbBuilder, struct token* tFunctionToken, struct ast_node** out_anNode);
char eval_stack_pop_return_stmt(struct expression_list_builder* elbBuilder, struct token* tReturnToken, struct ast_node** out_anNode);
char eval_stack_pop_if_stmt(struct expression_list_builder* elbBuilder, struct token* tIfToken, struct ast_node** out_anNode);
char eval_stack_pop_else_stmt(struct expression_list_builder* elbBuilder, struct token* tElseToken, struct ast_node** out_anNode);
char eval_stack_pop_call(struct expression_list_builder* elbBuilder, struct ast_node* anParNode, struct ast_node** out_anNode);
char pop_greater_precedence(struct expression_list_builder* elbBuilder, char iPrecedence);

#define CONTINUE_AST_PREDICATE_FUNCTION(NAME) char NAME(struct token* pToken, struct vector* vSyntaxErrors, void* pCtx)

CONTINUE_AST_PREDICATE_FUNCTION(is_eof_token);
CONTINUE_AST_PREDICATE_FUNCTION(is_close_parenthesis);

struct close_parenthesis_context {
    struct token* tOpenParenthesis;
    char cExpectedCloseParenthesis;
};

char flush_to_expression_list(struct expression_list_builder* elbBuilder, char iPrecedence);
char build_expression_list_separator(struct expression_list_builder* elbBuilder, struct token* tToken);
char build_expression_list_keyw(struct expression_list_builder* elbBuilder, struct token* tToken, char iParseMode, char iPrecedence);
char build_expression_list_literal(struct expression_list_builder* elbBuilder, struct token* tToken);
char build_expression_list_operator(struct expression_list_builder* elbBuilder, struct token* tToken, char bIsUnaryPref);
char build_expression_list_par(struct expression_list_builder* elbBuilder, struct token* tToken, struct token*** pptToken, char bSucceedsEval, char* out_bIsExpression);
char give_operator_following_expression(struct vector* vOperatorStack);
char build_expression_list(struct token*** pptToken, struct vector* vSyntaxErrors, CONTINUE_AST_PREDICATE_FUNCTION((*fpContinuePredicate)), void *pCtx, struct vector* out_vExpressionList);
char build_stmt_list_node(struct token** ptToken, struct vector* vSyntaxErrors, struct ast_node** out_anStmtListNode);

void print_ast_string(struct ast_elem* anRootElem, int indent);

#endif // AST_H