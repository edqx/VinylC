#include "ast.h"
#include <stdlib.h>
#include <memory.h>
#include <string.h>
#include <stdio.h>

struct syntax_error create_error(short uErrorCode, void* pSpecificContext) {
    struct syntax_error out = {};
    out.uErrorCode = uErrorCode;
    out.pSpecificCtx = pSpecificContext;
    return out;
}

void print_error(const char* pFileContent, struct syntax_error seSyntaxError) {
    switch (seSyntaxError.uErrorCode) {
    case SYNTAX_ERROR_NIL: break;
    case SYNTAX_ERROR_INVALID_UNARY_OPERATOR: SYNTAX_ERROR_PRINT(pFileContent, invalid_unary_operator, syntax_error_invalid_unary_operator_context, seSyntaxError); break;
    case SYNTAX_ERROR_EXPECTED_OPERATOR: SYNTAX_ERROR_PRINT(pFileContent, expected_operator, syntax_error_expected_operator_context, seSyntaxError); break;
    case SYNTAX_ERROR_VAR_STMT_EXPECTED_ASSIGNMENT: SYNTAX_ERROR_PRINT(pFileContent, var_stmt_expected_assignment, syntax_error_var_stmt_expected_assignment_context, seSyntaxError); break;
    case SYNTAX_ERROR_MISSING_RIGHT_HAND_OPERAND: SYNTAX_ERROR_PRINT(pFileContent, missing_right_hand_operand, syntax_error_missing_right_hand_operand_context, seSyntaxError); break;
    case SYNTAX_ERROR_VAR_STMT_EXPECTED_IDENTIFIER: SYNTAX_ERROR_PRINT(pFileContent, var_stmt_expected_identifier, syntax_error_var_stmt_expected_identifier_context, seSyntaxError); break;
    case SYNTAX_ERROR_INVALID_CLOSE_PARENTHESIS: SYNTAX_ERROR_PRINT(pFileContent, invalid_close_parenthesis, syntax_error_invalid_close_parenthesis_context, seSyntaxError); break;
    case SYNTAX_ERROR_UNMATCHED_CLOSE_PARENTHESIS: SYNTAX_ERROR_PRINT(pFileContent, unmatched_close_parenthesis, syntax_error_unmatched_close_parenthesis_context, seSyntaxError); break;
    case SYNTAX_ERROR_UNMATCHED_OPEN_PARENTHESIS: SYNTAX_ERROR_PRINT(pFileContent, unmatched_open_parenthesis, syntax_error_unmatched_open_parenthesis_context, seSyntaxError); break;
    case SYNTAX_ERROR_MISSING_FUNCTION_IMPL: SYNTAX_ERROR_PRINT(pFileContent, missing_function_impl, syntax_error_missing_function_impl_context, seSyntaxError); break;
    case SYNTAX_ERROR_MISSING_FUNCTION_DECL: SYNTAX_ERROR_PRINT(pFileContent, missing_function_decl, syntax_error_missing_function_decl_context, seSyntaxError); break;
    case SYNTAX_ERROR_INVALID_FUNCTION_DECL: SYNTAX_ERROR_PRINT(pFileContent, invalid_function_decl, syntax_error_invalid_function_decl_context, seSyntaxError); break;
    case SYNTAX_ERROR_INVALID_FUNCTION_NAME: SYNTAX_ERROR_PRINT(pFileContent, invalid_function_name, syntax_error_invalid_function_name_context, seSyntaxError); break;
    case SYNTAX_ERROR_MISSING_IF_CONDITION: SYNTAX_ERROR_PRINT(pFileContent, missing_if_condition, syntax_error_missing_if_condition_context, seSyntaxError); break;
    case SYNTAX_ERROR_MISSING_IF_BODY: SYNTAX_ERROR_PRINT(pFileContent, missing_if_body, syntax_error_missing_if_body_context, seSyntaxError); break;
    case SYNTAX_ERROR_IF_CONDITION_NOT_PARENTHESIZED: SYNTAX_ERROR_PRINT(pFileContent, if_condition_not_parenthesized, syntax_error_if_condition_not_parenthesized_context, seSyntaxError); break;
    default:
        printf("\x1b[91m[ERROR]: %i <not printed>\x1b[0m\n", seSyntaxError.uErrorCode);
        break;
    }
}

void recursive_get_ast_range(struct ast_elem* aeRootElem, struct file_input_idx_range** fiirRange) {
    switch (aeRootElem->iKind) {
    case AST_NODE_KIND_EMPTY:
        break;
    case AST_NODE_KIND_LITERAL:;
        struct ast_literal* literal = (struct ast_literal*)aeRootElem;
        if (*fiirRange == 0) {
            *fiirRange = malloc(sizeof(struct file_input_idx_range));
            **fiirRange = literal->tToken->fiirFileRange;
        }
        **fiirRange = contain_file_input_idx_range(**fiirRange, literal->tToken->fiirFileRange);
        break;
    default:
        struct ast_node* node = (struct ast_node*)aeRootElem;
        for (int i = 0; i < node->uNumElements; i++) {
            recursive_get_ast_range(node->ppElements[i], fiirRange);
        }
        break;
    }
}

SYNTAX_ERROR_PRINT_FUNCTION(invalid_unary_operator, syntax_error_invalid_unary_operator_context) {
    printf("\x1b[91m[ERROR]: Invalid unary operator: %s at %i..%i\x1b[0m\n", pContext->tToken->pContent, pContext->tToken->fiirFileRange.uStartIdx, pContext->tToken->fiirFileRange.uEndIdx);
}

SYNTAX_ERROR_PRINT_FUNCTION(expected_operator, syntax_error_expected_operator_context) {
    printf("\x1b[91m[ERROR]: Expected operator: %s at %i..%i\x1b[0m\n", pContext->tToken->pContent, pContext->tToken->fiirFileRange.uStartIdx, pContext->tToken->fiirFileRange.uEndIdx);
}

SYNTAX_ERROR_PRINT_FUNCTION(var_stmt_expected_assignment, syntax_error_var_stmt_expected_assignment_context) {
    struct file_input_idx_range* range = 0;
    if (pContext->aeOperator != 0) recursive_get_ast_range(pContext->aeOperator, &range);
    if (range == 0) {
        printf("\x1b[91m[ERROR]: Expected assignment at %i\x1b[0m\n", pContext->tVarToken->fiirFileRange.uEndIdx);
    } else {
        printf("\x1b[91m[ERROR]: Expected assignment at %i..%i\x1b[0m\n", range->uStartIdx, range->uEndIdx);
    }
    if (range != 0) free(range);
}

SYNTAX_ERROR_PRINT_FUNCTION(missing_right_hand_operand, syntax_error_missing_right_hand_operand_context) {
    printf("\x1b[91m[ERROR]: Expected right-hand operand for %s at %i..%i\x1b[0m\n", pContext->tToken->pContent, pContext->tToken->fiirFileRange.uStartIdx, pContext->tToken->fiirFileRange.uEndIdx);
}

SYNTAX_ERROR_PRINT_FUNCTION(var_stmt_expected_identifier, syntax_error_var_stmt_expected_identifier_context) {
    struct file_input_idx_range* range = 0;
    if (pContext->aeLeftHandElem != 0) recursive_get_ast_range(pContext->aeLeftHandElem, &range);
    if (range == 0) {
        printf("\x1b[91m[ERROR]: Expected identifier at %i\x1b[0m\n", pContext->tVarToken->fiirFileRange.uEndIdx);
    } else {
        printf("\x1b[91m[ERROR]: Expected identifier at %i..%i\x1b[0m\n", range->uStartIdx, range->uEndIdx);
        free(range);
    }
}

SYNTAX_ERROR_PRINT_FUNCTION(invalid_close_parenthesis, syntax_error_invalid_close_parenthesis_context) {
    char expectedClosePar = get_matching_close_parenthesis(pContext->tOpenParenthesis->pContent[0]);
    printf("\x1b[91m[ERROR]: Invalid close parenthesis at %i..%i, expected '%c', see %i..%i\x1b[0m\n",
        pContext->tCloseParenthesis->fiirFileRange.uStartIdx, pContext->tCloseParenthesis->fiirFileRange.uEndIdx,
        expectedClosePar, pContext->tOpenParenthesis->fiirFileRange.uStartIdx, pContext->tOpenParenthesis->fiirFileRange.uEndIdx);
}

SYNTAX_ERROR_PRINT_FUNCTION(unmatched_close_parenthesis, syntax_error_unmatched_close_parenthesis_context) {
    printf("\x1b[91m[ERROR]: Unmatched close parenthesis at %i..%i\x1b[0m\n",
        pContext->tCloseParenthesis->fiirFileRange.uStartIdx, pContext->tCloseParenthesis->fiirFileRange.uEndIdx);
}

SYNTAX_ERROR_PRINT_FUNCTION(unmatched_open_parenthesis, syntax_error_unmatched_open_parenthesis_context) {
    char expectedClosePar = get_matching_close_parenthesis(pContext->tOpenParenthesis->pContent[0]);
    printf("\x1b[91m[ERROR]: Unmatched open parenthesis, got EOF but expected '%c', see %i..%i\x1b[0m\n",
        expectedClosePar, pContext->tOpenParenthesis->fiirFileRange.uStartIdx, pContext->tOpenParenthesis->fiirFileRange.uEndIdx);
}

SYNTAX_ERROR_PRINT_FUNCTION(missing_function_impl, syntax_error_missing_function_impl_context) {
    struct file_input_idx_range* range = 0;
    if (pContext->aeFunctionCall != 0) recursive_get_ast_range((struct ast_elem*)pContext->aeFunctionCall, &range);
    if (pContext->alFunctionName != 0) {
        printf("\x1b[91m[ERROR]: Expected implementation for function '%s' at %i\x1b[0m\n", pContext->alFunctionName->tToken->pContent, range->uEndIdx);
    } else if (range != 0) {
        printf("\x1b[91m[ERROR]: Expected implementation of function at %i\x1b[0m\n", range->uEndIdx);
    } else {
        printf("\x1b[91m[ERROR]: Expected function implementation following '%s' at %i..%i\x1b[0m\n", pContext->tFunctionToken->pContent,
            pContext->tFunctionToken->fiirFileRange.uStartIdx, pContext->tFunctionToken->fiirFileRange.uEndIdx);
    }
    if (range != 0) free(range);
}

SYNTAX_ERROR_PRINT_FUNCTION(missing_function_decl, syntax_error_missing_function_decl_context) {
    printf("\x1b[91m[ERROR]: Expected function declaration following '%s' at %i..%i\x1b[0m\n", pContext->tFunctionToken->pContent,
        pContext->tFunctionToken->fiirFileRange.uStartIdx, pContext->tFunctionToken->fiirFileRange.uEndIdx);
}

SYNTAX_ERROR_PRINT_FUNCTION(invalid_function_decl, syntax_error_invalid_function_decl_context) {
    struct file_input_idx_range* range = 0;
    if (pContext->aeFunctionDecl != 0) recursive_get_ast_range(pContext->aeFunctionDecl, &range);
    if (range == 0) {
        printf("\x1b[91m[ERROR]: Invalid function declaration following '%s' at %i..%i\x1b[0m\n", pContext->tFunctionToken->pContent,
            pContext->tFunctionToken->fiirFileRange.uStartIdx, pContext->tFunctionToken->fiirFileRange.uEndIdx);
    } else {
        printf("\x1b[91m[ERROR]: Invalid function declaration at %i..%i\x1b[0m\n", range->uStartIdx, range->uEndIdx);
        free(range);
    }
}

SYNTAX_ERROR_PRINT_FUNCTION(invalid_function_name, syntax_error_invalid_function_name_context) {
    struct file_input_idx_range* range = 0;
    if (pContext->aeFunctionRef != 0) recursive_get_ast_range(pContext->aeFunctionRef, &range);
    if (range == 0) {
        printf("\x1b[91m[ERROR]: Invalid function name following '%s' at %i..%i\x1b[0m\n", pContext->tFunctionToken->pContent,
            pContext->tFunctionToken->fiirFileRange.uStartIdx, pContext->tFunctionToken->fiirFileRange.uEndIdx);
    } else {
        printf("\x1b[91m[ERROR]: Invalid function name at %i..%i\x1b[0m\n", range->uStartIdx, range->uEndIdx);
        free(range);
    }
}

SYNTAX_ERROR_PRINT_FUNCTION(missing_if_condition, syntax_error_missing_if_condition_context) {
    printf("\x1b[91m[ERROR]: Expected body for if statement at %i\x1b[0m\n", pContext->tIfToken->fiirFileRange.uEndIdx);
}

SYNTAX_ERROR_PRINT_FUNCTION(if_condition_not_parenthesized, syntax_error_if_condition_not_parenthesized_context) {
    struct file_input_idx_range* range = 0;
    if (pContext->aeIfCondition != 0) recursive_get_ast_range(pContext->aeIfCondition, &range);
    if (range == 0) {
        printf("\x1b[91m[ERROR]: Condition must be parenthesized following 'if' at %i\x1b[0m\n", pContext->tIfToken->fiirFileRange.uEndIdx);
    } else {
        printf("\x1b[91m[ERROR]: Condition must be parenthesized beginning at %i\x1b[0m\n", range->uStartIdx);
    }
}

SYNTAX_ERROR_PRINT_FUNCTION(missing_if_body, syntax_error_missing_if_body_context) {
    struct file_input_idx_range* range = 0;
    if (pContext->aeIfCondition != 0) recursive_get_ast_range(pContext->aeIfCondition, &range);
    if (range == 0) {
        printf("\x1b[91m[ERROR]: Expected body for if statement at %i\x1b[0m\n", pContext->tIfToken->fiirFileRange.uEndIdx);
    } else {
        printf("\x1b[91m[ERROR]: Expected body for if statement following condition at %i\x1b[0m\n", range->uEndIdx);
    }
}

struct ast_node create_ast_node() {
    struct ast_node out = {};
    return out;
}

char new_ast_node(struct ast_node** out_anNode) {
    struct ast_node* out = (struct ast_node*)malloc(sizeof(struct ast_node));
    memset(out, 0, sizeof(struct ast_node));
    if (out == 0) return AST_NODE_FAIL;
    *out_anNode = out;
    return AST_NODE_SUCCESS;
}

char assert_ast_node_not_initialized(struct ast_node* anSelf) {
    return anSelf->ppElements == 0 ? AST_NODE_SUCCESS : AST_NODE_FAIL;
}

char init_ast_node(struct ast_node* anSelf, char iKind, unsigned int uNumElements) {
    if (assert_ast_node_not_initialized(anSelf) == AST_NODE_FAIL) return AST_NODE_ALREADY_INITIALIZED;

    anSelf->iKind = iKind;
    anSelf->uNumElements = uNumElements;
    anSelf->ppElements = (struct ast_elem**)malloc(uNumElements * sizeof(struct ast_elem*));
    for (int i = 0; i < uNumElements; i++) {
        anSelf->ppElements[i] = (struct ast_elem*)malloc(sizeof(struct ast_elem));
        if (anSelf->ppElements[i] == 0) return AST_NODE_FAIL;
        anSelf->ppElements[i]->iKind = AST_NODE_KIND_EMPTY;
    }
    return AST_NODE_SUCCESS;
}

char replace_empty_node(struct ast_node* anSelf, struct ast_elem* anReplacement, unsigned int uElementIdx) {
    if (assert_ast_node_not_initialized(anSelf) == AST_NODE_SUCCESS) return AST_NODE_NOT_INITIALIZED;
    if (uElementIdx >= anSelf->uNumElements) return AST_NODE_OOB;
    if (anSelf->ppElements[uElementIdx]->iKind != AST_NODE_KIND_EMPTY) return AST_NODE_NOT_EMPTY_NODE;

    free(anSelf->ppElements[uElementIdx]);
    anSelf->ppElements[uElementIdx] = anReplacement;
    return AST_NODE_SUCCESS;
}

struct ast_literal create_ast_literal() {
    struct ast_literal out = {};
    return out;
}

char new_ast_literal(struct ast_literal** out_alLiteral) {
    struct ast_literal* out = (struct ast_literal*)malloc(sizeof(struct ast_literal));
    memset(out, 0, sizeof(struct ast_literal));
    if (out == 0) return AST_NODE_FAIL;
    *out_alLiteral = out;
    return AST_NODE_SUCCESS;
}

char assert_ast_literal_not_initialized(struct ast_literal* alSelf) {
    return alSelf->tToken == 0 ? AST_NODE_SUCCESS : AST_NODE_FAIL;
}

char init_ast_literal(struct ast_literal* alSelf, char iLiteralKind, struct token* tToken) {
    if (assert_ast_literal_not_initialized(alSelf) == AST_NODE_FAIL) return AST_NODE_ALREADY_INITIALIZED;
    alSelf->iKind = AST_NODE_KIND_LITERAL;
    alSelf->iLiteralKind = iLiteralKind;
    alSelf->tToken = tToken;
    return AST_NODE_SUCCESS;
}

char get_literal_token_kind(struct token* tToken) {
    switch (tToken->iKind) {
    case TOKEN_KIND_IDENT:
        return AST_LITERAL_KIND_IDENT;
    case TOKEN_KIND_NUMBER:
        return AST_LITERAL_KIND_NUM;
    case TOKEN_KIND_STR:
        return AST_LITERAL_KIND_STR;
    }
    return AST_LITERAL_KIND_NIL;
}

char allocate_ast_literal_from_token(struct token* tToken, struct ast_literal** out_alLiteral) {
    char literalTokenKind = get_literal_token_kind(tToken);
    if (literalTokenKind == AST_LITERAL_KIND_NIL) return AST_NODE_NOT_LITERAL_TOKEN;
    char eNewAst = new_ast_literal(out_alLiteral);
    if (eNewAst != AST_NODE_SUCCESS) return eNewAst;
    char eInit = init_ast_literal(*out_alLiteral, literalTokenKind, tToken);
    if (eInit != AST_NODE_SUCCESS) {
        free(*out_alLiteral);
        return eInit;
    }
    return AST_NODE_SUCCESS;
}

char can_operator_be_unary_pref(struct token* tToken) {
    return tToken->pContent[0] == '+' || (tToken->pContent[0] == '-' && tToken->pContent[1] == '\0') || tToken->pContent[0] == '@';
}

char can_operator_be_unary_suff(struct token* tToken) {
    return 0;
}

char get_operator_precedence(struct token* tToken, char iOperatorParseMode) {
    switch (tToken->iKind) {
    case TOKEN_KIND_OPERATOR:
        switch (tToken->pContent[0]) {
            case '.': return AST_PRECEDENCE_OPERATOR_ACCESS;
            case '+':
            case '-':
                switch (tToken->pContent[1]) {
                case '\0':
                    if (iOperatorParseMode == OPERATOR_PARSE_MODE_STANDALONE) return AST_PRECEDENCE_OPERATOR_ADD;
                    return iOperatorParseMode == OPERATOR_PARSE_MODE_BINARY ? AST_PRECEDENCE_OPERATOR_ADD : AST_PRECEDENCE_OPERATOR_UNARY_PREF;
                case '>': return AST_PRECEDENCE_OPERATOR_ACCESS;
                }
                break;
            case '=':
                switch (tToken->pContent[1]) {
                case '\0': return AST_PRECEDENCE_OPERATOR_ASSIGN;
                case '=': return AST_PRECEDENCE_OPERATOR_EQUAL;
                }
                break;
            case '>':
                switch (tToken->pContent[1]) {
                case '=': return AST_PRECEDENCE_OPERATOR_COMPARE;
                }
                break;
            case '<':
                switch (tToken->pContent[1]) {
                case '=': return AST_PRECEDENCE_OPERATOR_COMPARE;
                }
                break;
            case '*': return AST_PRECEDENCE_OPERATOR_MUL;
            case '/': return AST_PRECEDENCE_OPERATOR_MUL;
            case '%': return AST_PRECEDENCE_OPERATOR_MUL;
            case '|':
                switch (tToken->pContent[1]) {
                case '|': return AST_PRECEDENCE_OPERATOR_LOGIC_OR;
                }
                break;
            case '&':
                switch (tToken->pContent[1]) {
                case '\0': return AST_PRECEDENCE_OPERATOR_CONCAT;
                case '&': return AST_PRECEDENCE_OPERATOR_LOGIC_AND;
                }
                break;
            case '@': return AST_PRECEDENCE_OPERATOR_UNARY_PREF;
        }
        break;
    case TOKEN_KIND_IDENT:
        if (strcmp(tToken->pContent, "else") == 0) return AST_PRECEDENCE_STATEMENT_ELSE;
        if (strcmp(tToken->pContent, "return") == 0) return AST_PRECEDENCE_STATEMENT_RETURN;
        return AST_PRECEDENCE_STATEMENT;
    }
    return AST_PRECEDENCE_NIL;
}

char get_keyword_operator_parse_mode(const char* pIdentStr) {
    unsigned int len = strlen(pIdentStr);
    switch (len) {
        case 2:
            if (strcmp(pIdentStr, "if") == 0) return OPERATOR_PARSE_MODE_IF_STMT;
            break;
        case 3:
            if (strcmp(pIdentStr, "var") == 0) return OPERATOR_PARSE_MODE_VAR_STMT;
            break;
        case 4:
            if (strcmp(pIdentStr, "func") == 0) return OPERATOR_PARSE_MODE_IF_STMT;
            if (strcmp(pIdentStr, "type") == 0) return OPERATOR_PARSE_MODE_TYPE_STMT;
            if (strcmp(pIdentStr, "else") == 0) return OPERATOR_PARSE_MODE_ELSE_STMT;
            break;
        case 6:
            if (strcmp(pIdentStr, "return") == 0) return OPERATOR_PARSE_MODE_RETURN_STMT;
            break;
    }
    return OPERATOR_PARSE_MODE_NIL;
}

AST_ELEM_GET_LITERAL_FUNCTION(binary_operator, operator) AST_ELEM_GET_LITERAL_FUNCTION_IMPL(AST_NODE_KIND_BINARY_OPER, 0);
AST_ELEM_GET_FUNCTION(binary_operator, left_operand) AST_ELEM_GET_FUNCTION_IMPL(AST_NODE_KIND_BINARY_OPER, 1);
AST_ELEM_GET_FUNCTION(binary_operator, right_operand) AST_ELEM_GET_FUNCTION_IMPL(AST_NODE_KIND_BINARY_OPER, 2);

AST_ELEM_GET_LITERAL_FUNCTION(unary_operator, operator) AST_ELEM_GET_LITERAL_FUNCTION_IMPL(AST_NODE_KIND_BINARY_OPER, 0);
AST_ELEM_GET_FUNCTION(unary_operator, left_operand) AST_ELEM_GET_FUNCTION_IMPL(AST_NODE_KIND_BINARY_OPER, 1);

AST_ELEM_GET_LITERAL_FUNCTION(var_decl_stmt, var_name) AST_ELEM_GET_LITERAL_FUNCTION_IMPL(AST_NODE_KIND_VAR_DECL_STMT, 1);
AST_ELEM_GET_FUNCTION(var_decl_stmt, var_initializer) AST_ELEM_GET_FUNCTION_IMPL(AST_NODE_KIND_VAR_DECL_STMT, 2);

AST_ELEM_GET_FUNCTION(call, function_ref) AST_ELEM_GET_FUNCTION_IMPL(AST_NODE_KIND_CALL, 0);
AST_ELEM_GET_FUNCTION(call, params) AST_ELEM_GET_FUNCTION_IMPL(AST_NODE_KIND_CALL, 1);

AST_ELEM_GET_FUNCTION(if, condition) AST_ELEM_GET_FUNCTION_IMPL(AST_NODE_KIND_IF_STMT, 0);
AST_ELEM_GET_FUNCTION(if, block) AST_ELEM_GET_FUNCTION_IMPL(AST_NODE_KIND_IF_STMT, 1);
AST_ELEM_GET_FUNCTION(if, else_block) AST_ELEM_GET_FUNCTION_IMPL(AST_NODE_KIND_IF_STMT, 2);

char get_matching_close_parenthesis(char cOpenPar) {
    switch (cOpenPar) {
    case '(': return ')';
    case '{': return '}';
    case '[': return ']';
    }
    return '\0';
}

char get_parenthesis_node_construction_kind(char cOpenPar) {
    switch (cOpenPar) {
    case '(': return AST_NODE_KIND_PAR;
    case '{': return AST_NODE_KIND_BLOCK;
    case '[': return AST_NODE_KIND_TUPLE;
    }
    return AST_NODE_KIND_EMPTY;
}

struct expression_list_builder create_expression_list_builder() {
    struct expression_list_builder out = {};
    return out;
}

char init_expression_list_builder(struct expression_list_builder* elbSelf, struct vector* vSyntaxErrors, struct vector* vExpressionList) {
    elbSelf->vSyntaxErrors = vSyntaxErrors;
    elbSelf->vExpressionList = vExpressionList;

    elbSelf->vOperatorStack = new_vector();
    char eInit2 = init_vector(elbSelf->vOperatorStack, 512, sizeof(struct operator_pending_pop));
    if (eInit2 != VECTOR_SUCCESS) return AST_NODE_FAIL;
    elbSelf->vEvalStack = new_vector();
    char eInit3 = init_vector(elbSelf->vEvalStack, 512, sizeof(struct ast_elem*));
    if (eInit3 != VECTOR_SUCCESS) {
        deinit_vector(elbSelf->vOperatorStack);
        return AST_NODE_FAIL;
    }
    
    return AST_NODE_SUCCESS;
}

char deinit_expression_list_builder(struct expression_list_builder* elbSelf) {
    char eDeInit1 = deinit_vector(elbSelf->vOperatorStack);
    if (eDeInit1 != VECTOR_SUCCESS) return eDeInit1;
    free(elbSelf->vOperatorStack);
    char eDeInit2 = deinit_vector(elbSelf->vEvalStack);
    if (eDeInit2 != VECTOR_SUCCESS) return eDeInit2;
    free(elbSelf->vEvalStack);
    return AST_NODE_SUCCESS;
}

char eval_stack_pop_operator(struct expression_list_builder* elbBuilder, struct token* tOperatorToken, char bIsUnaryPref, char bIsUnarySuff, struct ast_node** out_anNode) {
    struct ast_elem* right = 0;
    struct ast_elem* left = 0;
    if (elbBuilder->vEvalStack->uLength == 0) {
        INSTANCE_SYNTAX_ERROR_CONTEXT(context, syntax_error_missing_right_hand_operand_context);
        context->tToken = tOperatorToken;
        REGISTER_SYNTAX_ERROR(elbBuilder->vSyntaxErrors, error, SYNTAX_ERROR_MISSING_RIGHT_HAND_OPERAND, context);
    } else {
        if (!bIsUnarySuff) {
            char ePopRight = vector_pop(elbBuilder->vEvalStack, (void*)&right);
            if (ePopRight != VECTOR_SUCCESS) return ePopRight;
        }
        
        if (!bIsUnaryPref) {
            char ePopLeft = vector_pop(elbBuilder->vEvalStack, (void*)&left);
            if (ePopLeft != VECTOR_SUCCESS) return ePopLeft;
        }
    }

    struct ast_node* operatorNode = 0;
    char eNewNode = new_ast_node(&operatorNode);
    if (eNewNode != AST_NODE_SUCCESS) return eNewNode;
    char eInitNode = init_ast_node(operatorNode, bIsUnaryPref ? AST_NODE_KIND_UNARY_OPER : AST_NODE_KIND_BINARY_OPER, (bIsUnarySuff && bIsUnaryPref) ? 1 : (bIsUnaryPref || bIsUnarySuff ? 2 : 3));
    if (eInitNode != AST_NODE_SUCCESS) {
        free(operatorNode);
        return eInitNode;
    }

    struct ast_literal* operatorLiteral = 0;
    char eNewLiteral = new_ast_literal(&operatorLiteral);
    if (eNewLiteral != AST_NODE_SUCCESS) {
        free(operatorNode);
        return eNewLiteral;
    }
    char eInitliteral = init_ast_literal(operatorLiteral, AST_LITERAL_KIND_OPER, tOperatorToken);
    if (eInitliteral != AST_NODE_SUCCESS) {
        free(operatorNode);
        free(operatorLiteral);
        return eInitliteral;
    }

    char eReplaceOperator = replace_empty_node(operatorNode, (struct ast_elem*)operatorLiteral, 0);
    if (eReplaceOperator != AST_NODE_SUCCESS) {
        free(operatorNode);
        free(operatorLiteral);
        return eReplaceOperator;
    }
    if (!bIsUnaryPref && left != 0) {
        char eReplaceLeftOperand = replace_empty_node(operatorNode, left, 1);
        if (eReplaceLeftOperand != AST_NODE_SUCCESS) {
            free(operatorNode);
            free(operatorLiteral);
            return eReplaceLeftOperand;
        }
    }
    if (!bIsUnarySuff && right != 0) {
        char eReplaceRightOperand = replace_empty_node(operatorNode, right, bIsUnaryPref ? 1 : 2);
        if (eReplaceRightOperand != AST_NODE_SUCCESS) {
            free(operatorNode);
            free(operatorLiteral);
            return eReplaceRightOperand;
        }
    }

    char eAppend = vector_append(elbBuilder->vEvalStack, (void*)&operatorNode);
    if (eAppend != VECTOR_SUCCESS) {
        free(operatorNode);
        free(operatorLiteral);
        return eAppend;
    }

    if (bIsUnarySuff && !can_operator_be_unary_suff(tOperatorToken)) {
        INSTANCE_SYNTAX_ERROR_CONTEXT(context, syntax_error_invalid_unary_operator_context);
        context->tToken = tOperatorToken;
        REGISTER_SYNTAX_ERROR(elbBuilder->vSyntaxErrors, error, SYNTAX_ERROR_INVALID_UNARY_OPERATOR, context);
    }

    if (bIsUnaryPref && !can_operator_be_unary_pref(tOperatorToken)) {
        INSTANCE_SYNTAX_ERROR_CONTEXT(context, syntax_error_invalid_unary_operator_context);
        context->tToken = tOperatorToken;
        REGISTER_SYNTAX_ERROR(elbBuilder->vSyntaxErrors, error, SYNTAX_ERROR_INVALID_UNARY_OPERATOR, context);
    }

    char eSuffixOperators = give_operator_following_expression(elbBuilder->vOperatorStack);
    if (eSuffixOperators != AST_NODE_SUCCESS) return eSuffixOperators;

    *out_anNode = operatorNode;
    return AST_NODE_SUCCESS;
}

char eval_stack_pop_var_stmt(struct expression_list_builder* elbBuilder, struct token* tVarToken, struct ast_node** out_anNode) {
    struct ast_elem* right = 0;
    if (elbBuilder->vEvalStack->uLength != 0) {
        char ePopRight = vector_shift(elbBuilder->vEvalStack, (void*)&right);
        if (ePopRight != VECTOR_SUCCESS) return ePopRight;
    }

    struct ast_node* assignment = (struct ast_node*)right;
    const char* operator = 0;
    char eGetBinaryOperator = AST_NODE_SUCCESS;
    if (right != 0) {
        eGetBinaryOperator = get_binary_operator_operator(right, &operator);
    }
    if (right == 0 || eGetBinaryOperator != AST_NODE_SUCCESS || strcmp(operator, "=") != 0) {
        INSTANCE_SYNTAX_ERROR_CONTEXT(context, syntax_error_var_stmt_expected_assignment_context);
        context->tVarToken = tVarToken;
        context->aeOperator = right;
        REGISTER_SYNTAX_ERROR(elbBuilder->vSyntaxErrors, error, SYNTAX_ERROR_VAR_STMT_EXPECTED_ASSIGNMENT, context);
        if (eGetBinaryOperator != AST_NODE_SUCCESS && eGetBinaryOperator != AST_NODE_WRONG_NODE_KIND) return eGetBinaryOperator;
    }
    
    struct ast_node* varDeclStmtNode = 0;
    char eNewNode = new_ast_node(&varDeclStmtNode);
    if (eNewNode != AST_NODE_SUCCESS) return eNewNode;
    char eInitNode = init_ast_node(varDeclStmtNode, AST_NODE_KIND_VAR_DECL_STMT, 3);
    if (eInitNode != AST_NODE_SUCCESS) {
        free(varDeclStmtNode);
        return eInitNode;
    }

    struct ast_literal* varTypeLiteral = 0;
    char eNewLiteral = new_ast_literal(&varTypeLiteral);
    if (eNewLiteral != AST_NODE_SUCCESS) {
        free(varDeclStmtNode);
        return eNewLiteral;
    }

    char eInitliteral = init_ast_literal(varTypeLiteral, AST_LITERAL_KIND_IDENT, tVarToken);
    if (eInitliteral != AST_NODE_SUCCESS) {
        free(varDeclStmtNode);
        free(varTypeLiteral);
        return eInitliteral;
    }

    struct ast_elem* leftOperand = 0;
    if (assignment != 0 && eGetBinaryOperator == AST_NODE_SUCCESS /* with invalid syntax, we might not even have a binary operator at all */) {
        char eGetLeftOperand = get_binary_operator_left_operand((struct ast_elem*)assignment, &leftOperand);
        if (eGetLeftOperand != AST_NODE_SUCCESS) {
            free(varDeclStmtNode);
            free(varTypeLiteral);
            return eGetLeftOperand;
        }
    }

    if (leftOperand != 0 && (leftOperand->iKind != AST_NODE_KIND_LITERAL || ((struct ast_literal*)leftOperand)->iLiteralKind != AST_LITERAL_KIND_IDENT)) {
        INSTANCE_SYNTAX_ERROR_CONTEXT(context, syntax_error_var_stmt_expected_identifier_context);
        context->tVarToken = tVarToken;
        context->aeLeftHandElem = leftOperand;
        REGISTER_SYNTAX_ERROR(elbBuilder->vSyntaxErrors, error, SYNTAX_ERROR_VAR_STMT_EXPECTED_IDENTIFIER, context);
    }

    struct ast_elem* rightOperand = 0;
    if (assignment != 0 && eGetBinaryOperator == AST_NODE_SUCCESS) {
        char eGetRightOperand = get_binary_operator_right_operand((struct ast_elem*)assignment, &rightOperand);
        if (eGetRightOperand != AST_NODE_SUCCESS) {
            free(varDeclStmtNode);
            free(varTypeLiteral);
            return eGetRightOperand;
        }
    }
    
    char eReplaceVarType = replace_empty_node(varDeclStmtNode, (struct ast_elem*)varTypeLiteral, 0);
    if (eReplaceVarType != AST_NODE_SUCCESS) {
        free(varDeclStmtNode);
        free(varTypeLiteral);
        return eReplaceVarType;
    }

    if (leftOperand != 0) {
        char eReplaceVarName = replace_empty_node(varDeclStmtNode, leftOperand, 1);
        if (eReplaceVarName != AST_NODE_SUCCESS) {
            free(varDeclStmtNode);
            free(varTypeLiteral);
            return eReplaceVarName;
        }
    }

    if (rightOperand != 0) {
        char eReplaceInitializer = replace_empty_node(varDeclStmtNode, rightOperand, 2);
        if (eReplaceInitializer != AST_NODE_SUCCESS) {
            free(varDeclStmtNode);
            free(varTypeLiteral);
            return eReplaceInitializer;
        }
    }

    char eAppend = vector_unshift(elbBuilder->vEvalStack, (void*)&varDeclStmtNode);
    if (eAppend != VECTOR_SUCCESS) {
        free(varDeclStmtNode);
        free(varTypeLiteral);
        return eAppend;
    }
    *out_anNode = varDeclStmtNode;
    return AST_NODE_SUCCESS;
}

char eval_stack_pop_function_decl(struct expression_list_builder* elbBuilder, struct token* tFunctionToken, struct ast_node** out_anNode) {
    struct ast_elem* functionCall = 0;
    if (elbBuilder->vEvalStack->uLength != 0) {
        char eShift = vector_shift(elbBuilder->vEvalStack, &functionCall);
        if (eShift != VECTOR_SUCCESS) return eShift;
    }
    struct ast_elem* codeBlock = 0;
    if (elbBuilder->vEvalStack->uLength != 0) {
        char eShift = vector_shift(elbBuilder->vEvalStack, &codeBlock);
        if (eShift != VECTOR_SUCCESS) return eShift;
    }

    struct ast_node* callNode = 0;
    struct ast_node* blockNode = 0;
    if (functionCall != 0 && functionCall->iKind == AST_NODE_KIND_CALL)
        callNode = (struct ast_node*)functionCall;
    if (codeBlock != 0)
        blockNode = (struct ast_node*)codeBlock;
    
    if (functionCall == 0) {
        INSTANCE_SYNTAX_ERROR_CONTEXT(errContext, syntax_error_missing_function_decl_context);
        errContext->tFunctionToken = tFunctionToken;
        REGISTER_SYNTAX_ERROR(elbBuilder->vSyntaxErrors, error, SYNTAX_ERROR_MISSING_FUNCTION_DECL, errContext);
    } else if (functionCall->iKind != AST_NODE_KIND_CALL) {
        INSTANCE_SYNTAX_ERROR_CONTEXT(errContext, syntax_error_invalid_function_decl_context);
        errContext->tFunctionToken = tFunctionToken;
        errContext->aeFunctionDecl = functionCall;
        REGISTER_SYNTAX_ERROR(elbBuilder->vSyntaxErrors, error, SYNTAX_ERROR_INVALID_FUNCTION_DECL, errContext);
    }
    if (functionCall != 0 && (codeBlock == 0 || codeBlock->iKind != AST_NODE_KIND_BLOCK)) {
        INSTANCE_SYNTAX_ERROR_CONTEXT(errContext, syntax_error_missing_function_impl_context);
        errContext->tFunctionToken = tFunctionToken;
        errContext->aeFunctionCall = functionCall;
        errContext->alFunctionName = 0;
        REGISTER_SYNTAX_ERROR(elbBuilder->vSyntaxErrors, error, SYNTAX_ERROR_MISSING_FUNCTION_IMPL, errContext);
    }
    
    struct ast_node* functionDeclNode = 0;
    char eNewNode = new_ast_node(&functionDeclNode);
    if (eNewNode != AST_NODE_SUCCESS) return eNewNode;
    char eInitNode = init_ast_node(functionDeclNode, AST_NODE_KIND_FUNCTION_DECL_STMT, 4);
    if (eInitNode != AST_NODE_SUCCESS) {
        free(functionDeclNode);
        return eInitNode;
    }

    struct ast_literal* functionTypeLiteral = 0;
    char eNewLiteral = new_ast_literal(&functionTypeLiteral);
    if (eNewLiteral != AST_NODE_SUCCESS) {
        free(functionDeclNode);
        return eNewLiteral;
    }

    char eInitliteral = init_ast_literal(functionTypeLiteral, AST_LITERAL_KIND_IDENT, tFunctionToken);
    if (eInitliteral != AST_NODE_SUCCESS) {
        free(functionDeclNode);
        free(functionTypeLiteral);
        return eInitliteral;
    }
    
    char eReplace1 = replace_empty_node(functionDeclNode, (struct ast_elem*)functionTypeLiteral, 0);
    if (eReplace1 != VECTOR_SUCCESS) {
        free(functionDeclNode);
        free(functionTypeLiteral);
        return eReplace1;
    }

    if (callNode != 0) {
        struct ast_elem* callFunctionRef = 0;
        struct ast_elem* callParams = 0;
        char eGetFunctionRef = get_call_function_ref((struct ast_elem*)callNode, &callFunctionRef);
        if (eGetFunctionRef != AST_NODE_SUCCESS) {
            free(functionDeclNode);
            free(functionTypeLiteral);
            return eGetFunctionRef;
        }
        char eGetFunctionParams = get_call_params((struct ast_elem*)callNode, &callParams);
        char eReplace1 = replace_empty_node(functionDeclNode, callFunctionRef, 1);
        if (eReplace1 != VECTOR_SUCCESS) {
            free(functionDeclNode);
            free(functionTypeLiteral);
            return eReplace1;
        }
        char eReplace2 = replace_empty_node(functionDeclNode, callParams, 2);
        if (eReplace2 != VECTOR_SUCCESS) {
            free(functionDeclNode);
            free(functionTypeLiteral);
            return eReplace2;
        }

        if (callFunctionRef->iKind != AST_NODE_KIND_LITERAL || ((struct ast_literal*)callFunctionRef)->iLiteralKind != AST_LITERAL_KIND_IDENT) {
            INSTANCE_SYNTAX_ERROR_CONTEXT(errContext, syntax_error_invalid_function_name_context);
            errContext->tFunctionToken = tFunctionToken;
            errContext->aeFunctionRef = callFunctionRef;
            REGISTER_SYNTAX_ERROR(elbBuilder->vSyntaxErrors, error, SYNTAX_ERROR_INVALID_FUNCTION_NAME, errContext);
        }

        free(callNode);
    }

    if (codeBlock != 0 && codeBlock->iKind == AST_NODE_KIND_BLOCK) {
        char eReplace = replace_empty_node(functionDeclNode, codeBlock, 3);
        if (eReplace != VECTOR_SUCCESS) {
            free(functionDeclNode);
            free(functionTypeLiteral);
            return eReplace;
        }
    }

    char eAppend = vector_unshift(elbBuilder->vEvalStack, (void*)&functionDeclNode);
    if (eAppend != VECTOR_SUCCESS) {
        free(functionDeclNode);
        free(functionTypeLiteral);
        return eAppend;
    }

    *out_anNode = functionDeclNode;
    return AST_NODE_SUCCESS;
}

char eval_stack_pop_return_stmt(struct expression_list_builder* elbBuilder, struct token* tReturnToken, struct ast_node** out_anNode) {
    struct ast_elem* returnExpr = 0;
    if (elbBuilder->vEvalStack->uLength != 0) {
        char ePop = vector_pop(elbBuilder->vEvalStack, (void*)&returnExpr);
        if (ePop != VECTOR_SUCCESS) return ePop;
    }
    
    struct ast_node* returnNode = 0;
    char eNewNode = new_ast_node(&returnNode);
    if (eNewNode != AST_NODE_SUCCESS) return eNewNode;
    char eInitNode = init_ast_node(returnNode, AST_NODE_KIND_RETURN_STMT, 1);
    if (eInitNode != AST_NODE_SUCCESS) {
        free(returnNode);
        return eInitNode;
    }

    if (returnExpr != 0) {
        char eReplace = replace_empty_node(returnNode, returnExpr, 0);
        if (eReplace != AST_NODE_SUCCESS) {
            free(returnNode);
            return eReplace;
        }
    }

    char eAppend = vector_append(elbBuilder->vEvalStack, (void*)&returnNode);
    if (eAppend != VECTOR_SUCCESS) {
        free(returnNode);
        return eAppend;
    }
    *out_anNode = returnNode;
    return AST_NODE_SUCCESS;
}

char eval_stack_pop_if_stmt(struct expression_list_builder* elbBuilder, struct token* tIfToken, struct ast_node** out_anNode) {struct ast_elem* returnExpr = 0;
    struct ast_elem* conditionElem = 0;
    if (elbBuilder->vEvalStack->uLength == 0) {
        INSTANCE_SYNTAX_ERROR_CONTEXT(context, syntax_error_missing_if_condition_context);
        context->tIfToken = tIfToken;
        REGISTER_SYNTAX_ERROR(elbBuilder->vSyntaxErrors, error, SYNTAX_ERROR_MISSING_IF_CONDITION, context);
    } else {
        char ePop = vector_shift(elbBuilder->vEvalStack, (void*)&conditionElem);
        if (ePop != VECTOR_SUCCESS) return ePop;
    }

    struct ast_elem* blockElem = 0;
    if (elbBuilder->vEvalStack->uLength == 0) {
        INSTANCE_SYNTAX_ERROR_CONTEXT(context, syntax_error_missing_if_body_context);
        context->tIfToken = tIfToken;
        context->aeIfCondition = conditionElem;
        REGISTER_SYNTAX_ERROR(elbBuilder->vSyntaxErrors, error, SYNTAX_ERROR_MISSING_IF_BODY, context);
    } else {
        char ePop = vector_shift(elbBuilder->vEvalStack, (void*)&blockElem);
        if (ePop != VECTOR_SUCCESS) return ePop;
    }

    if (conditionElem != 0 && conditionElem->iKind != AST_NODE_KIND_PAR) {
        INSTANCE_SYNTAX_ERROR_CONTEXT(context, syntax_error_if_condition_not_parenthesized_context);
        context->tIfToken = tIfToken;
        context->aeIfCondition = conditionElem;
        REGISTER_SYNTAX_ERROR(elbBuilder->vSyntaxErrors, error, SYNTAX_ERROR_IF_CONDITION_NOT_PARENTHESIZED, context);
    }
    
    struct ast_node* ifNode = 0;
    char eNewNode = new_ast_node(&ifNode);
    if (eNewNode != AST_NODE_SUCCESS) return eNewNode;
    char eInitNode = init_ast_node(ifNode, AST_NODE_KIND_IF_STMT, 3);
    if (eInitNode != AST_NODE_SUCCESS) {
        free(ifNode);
        return eInitNode;
    }

    char eReplaceCond = replace_empty_node(ifNode, conditionElem, 0);
    if (eReplaceCond != AST_NODE_SUCCESS) {
        free(ifNode);
        return eInitNode;
    }

    char eReplaceBody = replace_empty_node(ifNode, blockElem, 1);
    if (eReplaceBody != AST_NODE_SUCCESS) {
        free(ifNode);
        return eInitNode;
    }
    
    char eAppend = vector_append(elbBuilder->vEvalStack, (void*)&ifNode);
    if (eAppend != VECTOR_SUCCESS) {
        free(ifNode);
        return eAppend;
    }
    *out_anNode = ifNode;
    return AST_NODE_SUCCESS;
}

char eval_stack_pop_else_stmt(struct expression_list_builder* elbBuilder, struct token* tElseToken, struct ast_node** out_anNode) {
    struct ast_elem* lastIfStatement = 0;
    char ePopExpr = vector_at(elbBuilder->vExpressionList, elbBuilder->vExpressionList->uLength - 1, (void*)&lastIfStatement);
    if (ePopExpr != VECTOR_SUCCESS) return ePopExpr;

    if (lastIfStatement == 0) {
        // todo: error
    }
    
    struct ast_elem* elseElement = 0;
    char eGetElseBlock = get_if_else_block(lastIfStatement, &elseElement);
    if (eGetElseBlock != AST_NODE_SUCCESS) return eGetElseBlock;
    while (elseElement->iKind == AST_NODE_KIND_IF_STMT) {
        lastIfStatement = elseElement;
        eGetElseBlock = get_if_else_block(lastIfStatement, &elseElement);
        if (eGetElseBlock != AST_NODE_SUCCESS) return eGetElseBlock;
    }
    if (elseElement->iKind != AST_NODE_KIND_EMPTY) {
        // todo: error
    }

    struct ast_elem* conditionElem = 0;
    struct ast_elem* blockElem = 0;
    if (elbBuilder->vEvalStack->uLength != 0) {
        char ePop = vector_shift(elbBuilder->vEvalStack, (void*)&blockElem);
        if (ePop != VECTOR_SUCCESS) return ePop;
    }
    
    if (elbBuilder->vEvalStack->uLength != 0) {
        char ePop = vector_shift(elbBuilder->vEvalStack, (void*)&conditionElem);
        if (ePop != VECTOR_SUCCESS) return ePop;
    }

    if (conditionElem != 0) {
        struct ast_elem* tmp = conditionElem;
        conditionElem = blockElem;
        blockElem = tmp;
    }

    if (blockElem == 0) {
        INSTANCE_SYNTAX_ERROR_CONTEXT(context, syntax_error_missing_if_body_context);
        context->tIfToken = tElseToken;
        context->aeIfCondition = conditionElem;
        REGISTER_SYNTAX_ERROR(elbBuilder->vSyntaxErrors, error, SYNTAX_ERROR_MISSING_IF_BODY, context);
    }

    if (conditionElem != 0 && conditionElem->iKind != AST_NODE_KIND_PAR) {
        INSTANCE_SYNTAX_ERROR_CONTEXT(context, syntax_error_if_condition_not_parenthesized_context);
        context->tIfToken = tElseToken;
        context->aeIfCondition = conditionElem;
        REGISTER_SYNTAX_ERROR(elbBuilder->vSyntaxErrors, error, SYNTAX_ERROR_IF_CONDITION_NOT_PARENTHESIZED, context);
    }
    
    if (conditionElem != 0) {
        struct ast_node* elseIfNode = 0;
        char eNewNode = new_ast_node(&elseIfNode);
        if (eNewNode != AST_NODE_SUCCESS) return eNewNode;
        char eInitNode = init_ast_node(elseIfNode, AST_NODE_KIND_IF_STMT, 3);
        if (eInitNode != AST_NODE_SUCCESS) {
            free(elseIfNode);
            return eInitNode;
        }

        char eReplaceCond = replace_empty_node(elseIfNode, conditionElem, 0);
        if (eReplaceCond != AST_NODE_SUCCESS) {
            free(elseIfNode);
            return eInitNode;
        }

        char eReplaceBody = replace_empty_node(elseIfNode, blockElem, 1);
        if (eReplaceBody != AST_NODE_SUCCESS) {
            free(elseIfNode);
            return eInitNode;
        }

        char eReplaceLastIf = replace_empty_node((struct ast_node*)lastIfStatement, (struct ast_elem*)elseIfNode, 2);
        if (eReplaceLastIf != AST_NODE_SUCCESS) {
            free(elseIfNode);
            return eReplaceLastIf;
        }
    } else if (blockElem) {
        char eReplaceLastIf = replace_empty_node((struct ast_node*)lastIfStatement, (struct ast_elem*)blockElem, 2);
        if (eReplaceLastIf != AST_NODE_SUCCESS) return eReplaceLastIf;
    }
    return AST_NODE_SUCCESS;
}

char eval_stack_pop_call(struct expression_list_builder* elbBuilder, struct ast_node* anParNode, struct ast_node** out_anNode) {
    struct ast_elem* functionRef = 0;
    if (elbBuilder->vEvalStack->uLength == 0) return AST_NODE_UNDEFINED_FUNCTION_CALL; // this should never happen
    char ePop = vector_pop(elbBuilder->vEvalStack, (void*)&functionRef);
    if (ePop != VECTOR_SUCCESS) return ePop;
    
    struct ast_node* callNode = 0;
    char eNewNode = new_ast_node(&callNode);
    if (eNewNode != AST_NODE_SUCCESS) return eNewNode;
    char eInitNode = init_ast_node(callNode, AST_NODE_KIND_CALL, 2);
    if (eInitNode != AST_NODE_SUCCESS) {
        free(callNode);
        return eInitNode;
    }

    char eReplaceRef = replace_empty_node(callNode, functionRef, 0);
    if (eReplaceRef != AST_NODE_SUCCESS) {
        free(callNode);
        return eReplaceRef;
    }

    char eReplaceParams = replace_empty_node(callNode, (struct ast_elem*)anParNode, 1);
    if (eReplaceParams != AST_NODE_SUCCESS) {
        free(callNode);
        return eReplaceParams;
    }

    char eAppend = vector_append(elbBuilder->vEvalStack, (void*)&callNode);
    if (eAppend != VECTOR_SUCCESS) {
        free(callNode);
        return eAppend;
    }
    *out_anNode = callNode;
    return AST_NODE_SUCCESS;
}

char pop_greater_precedence(struct expression_list_builder* elbBuilder, char iPrecedence) {
    while (elbBuilder->vOperatorStack->uLength > 0) { // shunting-yard, we'll pop until this token precedence is greater
        struct operator_pending_pop lastOperatorPending;
        char eLastOp = vector_at(elbBuilder->vOperatorStack, elbBuilder->vOperatorStack->uLength - 1, (void*)&lastOperatorPending);
        if (eLastOp != VECTOR_SUCCESS) return AST_NODE_FAIL;

        char p = get_operator_precedence(lastOperatorPending.tToken, lastOperatorPending.iOperatorParseMode);
        if (iPrecedence > p) break;

        char ePop = vector_pop(elbBuilder->vOperatorStack, 0);
        if (ePop != VECTOR_SUCCESS) return ePop;

        struct ast_node* operatorNode;
        char eStackPop = AST_NODE_FAIL;
        switch (lastOperatorPending.iOperatorParseMode) {
        case OPERATOR_PARSE_MODE_BINARY:
        case OPERATOR_PARSE_MODE_UNARY_PREF:
        case OPERATOR_PARSE_MODE_UNARY_SUFF:
        case OPERATOR_PARSE_MODE_STANDALONE:
            char isUnaryPref = lastOperatorPending.iOperatorParseMode == OPERATOR_PARSE_MODE_UNARY_PREF || lastOperatorPending.iOperatorParseMode == OPERATOR_PARSE_MODE_STANDALONE;
            char isUnarySuff = lastOperatorPending.iOperatorParseMode == OPERATOR_PARSE_MODE_UNARY_SUFF | lastOperatorPending.iOperatorParseMode == OPERATOR_PARSE_MODE_STANDALONE;
            eStackPop = eval_stack_pop_operator(elbBuilder, lastOperatorPending.tToken, isUnaryPref, isUnarySuff, &operatorNode);
            break;
        case OPERATOR_PARSE_MODE_VAR_STMT:
            eStackPop = eval_stack_pop_var_stmt(elbBuilder, lastOperatorPending.tToken, &operatorNode);
            break;
        case OPERATOR_PARSE_MODE_FUNCTION_STMT:
            eStackPop = eval_stack_pop_function_decl(elbBuilder, lastOperatorPending.tToken, &operatorNode);
            break;
        case OPERATOR_PARSE_MODE_TYPE_STMT:
            break;
        case OPERATOR_PARSE_MODE_RETURN_STMT:
            eStackPop = eval_stack_pop_return_stmt(elbBuilder, lastOperatorPending.tToken, &operatorNode);
            break;
        case OPERATOR_PARSE_MODE_IF_STMT:
            eStackPop = eval_stack_pop_if_stmt(elbBuilder, lastOperatorPending.tToken, &operatorNode);
            break;
        case OPERATOR_PARSE_MODE_ELSE_STMT:
            eStackPop = eval_stack_pop_else_stmt(elbBuilder, lastOperatorPending.tToken, &operatorNode);
            break;
        }
        if (eStackPop != AST_NODE_SUCCESS) return eStackPop;
    }
    return AST_NODE_SUCCESS;
}

CONTINUE_AST_PREDICATE_FUNCTION(is_eof_token) {
    return pToken->iKind == TOKEN_KIND_EOF ? AST_NODE_STOP : AST_NODE_SUCCESS;
}

CONTINUE_AST_PREDICATE_FUNCTION(is_close_parenthesis) {
    struct close_parenthesis_context* closeParContext = (struct close_parenthesis_context*)pCtx;
    if (pToken->iKind == TOKEN_KIND_EOF) {
        INSTANCE_SYNTAX_ERROR_CONTEXT(errContext, syntax_error_unmatched_open_parenthesis_context);
        errContext->tOpenParenthesis = closeParContext->tOpenParenthesis;
        REGISTER_SYNTAX_ERROR(vSyntaxErrors, error, SYNTAX_ERROR_UNMATCHED_OPEN_PARENTHESIS, errContext);
        return AST_NODE_STOP;
    }

    if (pToken->iKind != TOKEN_KIND_PAR_CLOSE) return AST_NODE_SUCCESS;

    if (closeParContext->cExpectedCloseParenthesis != pToken->pContent[0]) {
        INSTANCE_SYNTAX_ERROR_CONTEXT(errContext, syntax_error_invalid_close_parenthesis_context);
        errContext->tCloseParenthesis = pToken;
        errContext->tOpenParenthesis = closeParContext->tOpenParenthesis;
        REGISTER_SYNTAX_ERROR(vSyntaxErrors, error, SYNTAX_ERROR_INVALID_CLOSE_PARENTHESIS, errContext);
        return AST_NODE_STOP;
    }
    return AST_NODE_STOP;
}

char flush_to_expression_list(struct expression_list_builder* elbBuilder, char iPrecedence) {
    if (elbBuilder->vOperatorStack->uLength > 0) {
        char ePop = pop_greater_precedence(elbBuilder, iPrecedence);
        if (ePop != AST_NODE_SUCCESS) return ePop;
    }
    
    if (elbBuilder->vEvalStack->uLength > 0) {
        char eConcat = vector_append_concat(elbBuilder->vExpressionList, elbBuilder->vEvalStack);
        if (eConcat != VECTOR_SUCCESS) return eConcat;
        char eClear1 = vector_clear(elbBuilder->vEvalStack);
        if (eClear1 != VECTOR_SUCCESS) return eClear1;
    }
    return AST_NODE_SUCCESS;
}

char build_expression_list_separator(struct expression_list_builder* elbBuilder, struct token* tToken) {
    char eFlush = flush_to_expression_list(elbBuilder, 0);
    if (eFlush != AST_NODE_SUCCESS) return eFlush;
    return AST_NODE_SUCCESS;
}

char build_expression_list_keyw(struct expression_list_builder* elbBuilder, struct token* tToken, char iParseMode, char iPrecedece) {
    char eFlush = flush_to_expression_list(elbBuilder, iPrecedece);
    if (eFlush != AST_NODE_SUCCESS) return eFlush;
    
    struct operator_pending_pop operatorPending;
    operatorPending.tToken = tToken;
    operatorPending.iOperatorParseMode = iParseMode;
    char eAddOp = vector_append(elbBuilder->vOperatorStack, (void*)&operatorPending);
    if (eAddOp != VECTOR_SUCCESS) return eAddOp;
    return AST_NODE_SUCCESS;
}

char build_expression_list_literal(struct expression_list_builder* elbBuilder, struct token* tToken) {
    struct ast_literal* literal = 0;
    char eAllocAst = allocate_ast_literal_from_token(tToken, &literal);
    if (eAllocAst != AST_NODE_SUCCESS) return eAllocAst;

    char eAddLit = vector_append(elbBuilder->vEvalStack, (void*)&literal);
    if (eAddLit != VECTOR_SUCCESS) return eAddLit;
    return AST_NODE_SUCCESS;
}

char build_expression_list_operator(struct expression_list_builder* elbBuilder, struct token* tToken, char bIsUnaryPref) {
    if (elbBuilder->vOperatorStack->uLength > 0) {
        char p = get_operator_precedence(tToken, bIsUnaryPref ? OPERATOR_PARSE_MODE_UNARY_PREF : OPERATOR_PARSE_MODE_BINARY);
        char ePop = pop_greater_precedence(elbBuilder, p);
        if (ePop != AST_NODE_SUCCESS) return ePop;
    }

    struct operator_pending_pop operatorPending;
    operatorPending.tToken = tToken;
    operatorPending.iOperatorParseMode = bIsUnaryPref ? OPERATOR_PARSE_MODE_STANDALONE : OPERATOR_PARSE_MODE_UNARY_SUFF;
    char eAddOp = vector_append(elbBuilder->vOperatorStack, (void*)&operatorPending);
    if (eAddOp != VECTOR_SUCCESS) return eAddOp;
    return AST_NODE_SUCCESS;
}

char build_expression_list_par(struct expression_list_builder* elbBuilder, struct token* tToken, struct token*** pptToken, char bSucceedsEval, char* out_bIsExpression) {
    struct vector expressionList = create_vector();
    char eInit = init_vector(&expressionList, 512, sizeof(struct ast_elem*));
    if (eInit != VECTOR_SUCCESS) return AST_NODE_FAIL;
    char closingPar = get_matching_close_parenthesis(tToken->pContent[0]);
    if (closingPar == '\0') return AST_NODE_INVALID_PARENTHESIS;
    (*pptToken)++;
    struct close_parenthesis_context closeParenthesisContext;
    closeParenthesisContext.cExpectedCloseParenthesis = closingPar;
    closeParenthesisContext.tOpenParenthesis = tToken;
    char eRecurseBuildExpressions = build_expression_list(pptToken, elbBuilder->vSyntaxErrors, is_close_parenthesis, &closeParenthesisContext, &expressionList);
    if (eRecurseBuildExpressions != AST_NODE_SUCCESS) return eRecurseBuildExpressions;
    struct ast_node* parNode;
    char eNewNode = new_ast_node(&parNode);
    if (eNewNode != AST_NODE_SUCCESS) return eNewNode;
    char nodeKind = get_parenthesis_node_construction_kind(tToken->pContent[0]);
    char eInitNode = init_ast_node(parNode, nodeKind, expressionList.uLength);
    if (eInitNode != AST_NODE_SUCCESS) {
        free(parNode);
        return eInitNode;
    }
    for (int i = 0; i < expressionList.uLength; i++) {
        struct ast_elem* evalElem;
        vector_at(&expressionList, i, (void*)&evalElem);
        char eReplace = replace_empty_node(parNode, evalElem, i);
        if (eReplace != AST_NODE_SUCCESS) return eReplace;
    }
    char eDeInit = deinit_vector(&expressionList);
    if (eDeInit != VECTOR_SUCCESS) {
        free(parNode);
        return eDeInit;
    }
    switch (nodeKind) {
    case AST_NODE_KIND_PAR:
        if (bSucceedsEval) {
            struct ast_node* callNode;
            char ePopCall = eval_stack_pop_call(elbBuilder, parNode, &callNode);
            if (ePopCall != AST_NODE_SUCCESS) {
                deinit_vector(elbBuilder->vOperatorStack);
                deinit_vector(elbBuilder->vEvalStack);
                return ePopCall;
            }
        } else {
            char eAddPar = vector_append(elbBuilder->vEvalStack, (void*)&parNode);
            if (eAddPar != VECTOR_SUCCESS) return eAddPar;
        }
        *out_bIsExpression = 1;
        break;
    case AST_NODE_KIND_TUPLE:
        *out_bIsExpression = 1;
        char eAddTuple = vector_append(elbBuilder->vEvalStack, (void*)&parNode);
        if (eAddTuple != VECTOR_SUCCESS) return eAddTuple;
        break;
    case AST_NODE_KIND_BLOCK:
        *out_bIsExpression = 0;
        char eAddBlock = vector_append(elbBuilder->vEvalStack, (void*)&parNode);
        if (eAddBlock != VECTOR_SUCCESS) return eAddBlock;
        char eFlush = flush_to_expression_list(elbBuilder, AST_PRECEDENCE_STATEMENT);
        if (eFlush != AST_NODE_SUCCESS) return eFlush;
        break;
    }
    if ((**pptToken)->iKind == TOKEN_KIND_EOF) // break out of each loop in the recursion stack
        --*pptToken; // i hate myself for this.. but it works :3
    return AST_NODE_SUCCESS;
}

char give_operator_following_expression(struct vector* vOperatorStack) {
    if (vOperatorStack->uLength > 0) {
        struct operator_pending_pop* lastOpRef = 0;
        char eGetRef = vector_at_ref(vOperatorStack, vOperatorStack->uLength - 1, (void**)&lastOpRef);
        if (eGetRef != AST_NODE_SUCCESS) return eGetRef;
        switch (lastOpRef->iOperatorParseMode) {
        case OPERATOR_PARSE_MODE_STANDALONE:
            lastOpRef->iOperatorParseMode = OPERATOR_PARSE_MODE_UNARY_PREF;
            break;
        case OPERATOR_PARSE_MODE_UNARY_SUFF:
            lastOpRef->iOperatorParseMode = OPERATOR_PARSE_MODE_BINARY;
            break;
        }
    }
    return AST_NODE_SUCCESS;
}

char build_expression_list(struct token*** pptToken, struct vector* vSyntaxErrors, CONTINUE_AST_PREDICATE_FUNCTION((*fpContinuePredicate)), void* pCtx, struct vector* out_vExpressionList) {
    struct expression_list_builder elbBuilder = create_expression_list_builder();
    char eInit = init_expression_list_builder(&elbBuilder, vSyntaxErrors, out_vExpressionList);
    if (eInit != AST_NODE_SUCCESS) return eInit;
    char lastTransformedTokenValidOperand = 0;
    char eContinuePredicate = 0;
    for (; (eContinuePredicate = fpContinuePredicate(**pptToken, vSyntaxErrors, pCtx)) == AST_NODE_SUCCESS; (*pptToken)++) {
        struct token* token = **pptToken;
        if (token->iKind == TOKEN_KIND_SEPARATOR) {
            char eBuildSep = build_expression_list_separator(&elbBuilder, token);
            if (eBuildSep != AST_NODE_SUCCESS) {
                deinit_expression_list_builder(&elbBuilder);
                return eBuildSep;
            }
            lastTransformedTokenValidOperand = 0;
            continue;
        }
        if (token->iKind == TOKEN_KIND_IDENT) {
            char parseMode = get_keyword_operator_parse_mode(token->pContent);
            if (parseMode != OPERATOR_PARSE_MODE_NIL) {
                char precedence = get_operator_precedence(token, parseMode);
                char eBuildKeyw = build_expression_list_keyw(&elbBuilder, token, parseMode, precedence);
                if (eBuildKeyw != AST_NODE_SUCCESS) {
                    deinit_expression_list_builder(&elbBuilder);
                    return eBuildKeyw;
                }
                lastTransformedTokenValidOperand = 0;
                continue;
            }
        }
        switch (token->iKind) {
        case TOKEN_KIND_NUMBER:
        case TOKEN_KIND_STR:
        case TOKEN_KIND_IDENT:
            if (lastTransformedTokenValidOperand == 1) {
                INSTANCE_SYNTAX_ERROR_CONTEXT(context, syntax_error_expected_operator_context);
                context->tToken = token;
                REGISTER_SYNTAX_ERROR(vSyntaxErrors, error, SYNTAX_ERROR_EXPECTED_OPERATOR, context);
            }
            char eBuildLiteral = build_expression_list_literal(&elbBuilder, token);
            if (eBuildLiteral != AST_NODE_SUCCESS) {
                deinit_expression_list_builder(&elbBuilder);
                return eBuildLiteral;
            }
            lastTransformedTokenValidOperand = 1;
            char eSuffixOperators = give_operator_following_expression(elbBuilder.vOperatorStack);
            if (eSuffixOperators != AST_NODE_SUCCESS) {
                deinit_expression_list_builder(&elbBuilder);
                return eBuildLiteral;
            }
            break;
        case TOKEN_KIND_OPERATOR:
            char eBuildOper = build_expression_list_operator(&elbBuilder, token, !lastTransformedTokenValidOperand);
            if (eBuildOper != AST_NODE_SUCCESS) {
                deinit_expression_list_builder(&elbBuilder);
                return eBuildOper;
            }
            lastTransformedTokenValidOperand = 0;
            break;
        case TOKEN_KIND_PAR_OPEN:
            char isExpression = 0;
            char eBuildPar = build_expression_list_par(&elbBuilder, token, pptToken, lastTransformedTokenValidOperand, &isExpression);
            if (eBuildPar != AST_NODE_SUCCESS) {
                deinit_expression_list_builder(&elbBuilder);
                return eBuildPar;
            }
            lastTransformedTokenValidOperand = isExpression;
            if (isExpression) {
                char eSuffixOperators = give_operator_following_expression(elbBuilder.vOperatorStack);
                if (eSuffixOperators != AST_NODE_SUCCESS) {
                    deinit_expression_list_builder(&elbBuilder);
                    return eBuildLiteral;
                }
            }
            break;
        case TOKEN_KIND_PAR_CLOSE:
            INSTANCE_SYNTAX_ERROR_CONTEXT(errContext, syntax_error_unmatched_close_parenthesis_context);
            errContext->tCloseParenthesis = token;
            REGISTER_SYNTAX_ERROR(vSyntaxErrors, error, SYNTAX_ERROR_UNMATCHED_CLOSE_PARENTHESIS, errContext);
            break;
        }
    }

    if (eContinuePredicate != AST_NODE_STOP) {
        deinit_expression_list_builder(&elbBuilder);
        return eContinuePredicate;
    }

    char eFlush = flush_to_expression_list(&elbBuilder, 0);
    if (eFlush != AST_NODE_SUCCESS) return eFlush;

    deinit_expression_list_builder(&elbBuilder);
    return AST_NODE_SUCCESS;
}

char build_stmt_list_node(struct token** ptToken, struct vector* vSyntaxErrors, struct ast_node** out_anStmtListNode) {
    struct vector expressionList = create_vector();
    char eInit = init_vector(&expressionList, 512, sizeof(struct ast_elem*));
    if (eInit != VECTOR_SUCCESS) return AST_NODE_FAIL;
    char eBuildExpressionList = build_expression_list(&ptToken, vSyntaxErrors, is_eof_token, 0, &expressionList);
    if (eBuildExpressionList != AST_NODE_SUCCESS) return eBuildExpressionList;

    char eNewNode = new_ast_node(out_anStmtListNode);
    if (eNewNode != AST_NODE_SUCCESS) return eNewNode;
    char eInitNode = init_ast_node(*out_anStmtListNode, AST_NODE_KIND_STMT_LIST, expressionList.uLength);
    if (eInitNode != AST_NODE_SUCCESS) {
        free(*out_anStmtListNode);
        return eInitNode;
    }
    for (int i = 0; i < expressionList.uLength; i++) {
        struct ast_elem* evalElem;
        vector_at(&expressionList, i, (void*)&evalElem);
        char eReplace = replace_empty_node(*out_anStmtListNode, evalElem, i);
        if (eReplace != AST_NODE_SUCCESS) return eReplace;
    }

    deinit_vector(&expressionList);
}

void print_ast_string(struct ast_elem* anRootElem, int indent) {
    int indent2 = indent;
    while (indent2 > 0) {
        printf("    ");
        indent2--;
    }
    switch (anRootElem->iKind) {
    case AST_NODE_KIND_EMPTY:
        printf("(empty)\n");
        break;
    case AST_NODE_KIND_LITERAL:;
        struct ast_literal* literal = (struct ast_literal*)anRootElem;
        if (literal->iLiteralKind == AST_LITERAL_KIND_STR) {
            printf("AST LITERAL: \"%s\" (%i)\n", literal->tToken->pContent, literal->iLiteralKind);
        } else {
            printf("AST LITERAL: %s (%i)\n", literal->tToken->pContent, literal->iLiteralKind);
        }
        break;
    default:
        struct ast_node* node = (struct ast_node*)anRootElem;
        printf("AST NODE (%i) (%i %s)\n", anRootElem->iKind, node->uNumElements, node->uNumElements == 1 ? "element" : "elements");
        for (int i = 0; i < node->uNumElements; i++) {
            print_ast_string(node->ppElements[i], indent + 1);
        }
        break;
    }
}