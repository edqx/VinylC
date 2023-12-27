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
    case SYNTAX_ERROR_NIL:
        break;
    case SYNTAX_ERROR_INVALID_UNARY_OPERATOR:
        SYNTAX_ERROR_PRINT(pFileContent, invalid_unary_operator, syntax_error_invalid_unary_operator_context, seSyntaxError);
        break;
    case SYNTAX_ERROR_EXPECTED_OPERATOR:
        SYNTAX_ERROR_PRINT(pFileContent, expected_operator, syntax_error_expected_operator_context, seSyntaxError);
        break;
    case SYNTAX_ERROR_VAR_STMT_EXPECTED_ASSIGNMENT:
        SYNTAX_ERROR_PRINT(pFileContent, var_stmt_expected_assignment, syntax_error_var_stmt_expected_assignment_context, seSyntaxError);
        break;
    case SYNTAX_ERROR_MISSING_RIGHT_HAND_OPERAND:
        SYNTAX_ERROR_PRINT(pFileContent, missing_right_hand_operand, syntax_error_missing_right_hand_operand_context, seSyntaxError);
        break;
    case SYNTAX_ERROR_VAR_STMT_EXPECTED_IDENTIFIER:
        SYNTAX_ERROR_PRINT(pFileContent, var_stmt_expected_identifier, syntax_error_var_stmt_expected_identifier_context, seSyntaxError);
        break;
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
        for (int i = 0; i < node->uNumSons; i++) {
            recursive_get_ast_range(node->ppSons[i], fiirRange);
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
    }
    if (range != 0) free(range);
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
    return anSelf->ppSons == 0 ? AST_NODE_SUCCESS : AST_NODE_FAIL;
}

char init_ast_node(struct ast_node* anSelf, char iKind, unsigned int uNumSons) {
    if (assert_ast_node_not_initialized(anSelf) == AST_NODE_FAIL) return AST_NODE_ALREADY_INITIALIZED;

    anSelf->iKind = iKind;
    anSelf->uNumSons = uNumSons;
    anSelf->ppSons = (struct ast_elem**)malloc(uNumSons * sizeof(struct ast_elem*));
    for (int i = 0; i < uNumSons; i++) {
        anSelf->ppSons[i] = (struct ast_elem*)malloc(sizeof(struct ast_elem));
        if (anSelf->ppSons[i] == 0) return AST_NODE_FAIL;
        anSelf->ppSons[i]->iKind = AST_NODE_KIND_EMPTY;
    }
    return AST_NODE_SUCCESS;
}

char replace_empty_node(struct ast_node* anSelf, struct ast_elem* anReplacement, unsigned int uSonIdx) {
    if (assert_ast_node_not_initialized(anSelf) == AST_NODE_SUCCESS) return AST_NODE_NOT_INITIALIZED;
    if (uSonIdx >= anSelf->uNumSons) return AST_NODE_OOB;
    if (anSelf->ppSons[uSonIdx]->iKind != AST_NODE_KIND_EMPTY) return AST_NODE_NOT_EMPTY_NODE;

    free(anSelf->ppSons[uSonIdx]);
    anSelf->ppSons[uSonIdx] = anReplacement;
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

char can_operator_be_unary(struct token* tToken) {
    return tToken->pContent[0] == '+' || (tToken->pContent[0] == '-' && tToken->pContent[1] == '\0');
}

char get_operator_precedence(struct token* tToken, char iOperatorParseMode) {
    switch (tToken->iKind) {
    case TOKEN_KIND_OPERATOR:
        switch (tToken->pContent[0]) {
            case '.':
                return AST_PRECEDENCE_OPERATOR_ACCESS;
            case '-':
                switch (tToken->pContent[1]) {
                case '\0': // "-"
                    return iOperatorParseMode == OPERATOR_PARSE_MODE_BINARY ? AST_PRECEDENCE_OPERATOR_ADD : AST_PRECEDENCE_OPERATOR_UNARY_PREF;
                case '>': // "->"
                    return AST_PRECEDENCE_OPERATOR_ACCESS;
                }
                break;
            case '=':
                switch (tToken->pContent[1]) {
                case '\0': // "="
                    return AST_PRECEDENCE_OPERATOR_ASSIGN;
                case '=': // "=="
                    return AST_PRECEDENCE_OPERATOR_EQUAL;
                }
                break;
            case '>':
                switch (tToken->pContent[1]) {
                case '=': // >=
                    return AST_PRECEDENCE_OPERATOR_COMPARE;
                }
                break;
            case '<':
                switch (tToken->pContent[1]) {
                case '=': // <=
                    return AST_PRECEDENCE_OPERATOR_COMPARE;
                }
                break;
            case '+':
                return AST_PRECEDENCE_OPERATOR_ADD;
            case '*':
                return AST_PRECEDENCE_OPERATOR_MUL;
            case '/':
                return AST_PRECEDENCE_OPERATOR_MUL;
            case '%':
                return AST_PRECEDENCE_OPERATOR_MUL;
            case '|':
                switch (tToken->pContent[1]) {
                case '|': // "||"
                    return AST_PRECEDENCE_OPERATOR_LOGIC_OR;
                }
                break;
            case '&':
                switch (tToken->pContent[1]) {
                case '\0': // "&"
                    return AST_PRECEDENCE_OPERATOR_CONCAT;
                case '&': // "&&"
                    return AST_PRECEDENCE_OPERATOR_LOGIC_AND;
                }
                break;
        }
        break;
        case TOKEN_KIND_IDENT:
            return AST_PRECEDENCE_STATEMENT;
    }
    return AST_PRECEDENCE_NIL;
}

char get_keyword_operator_parse_mode(const char* pIdentStr) {
    unsigned int len = strlen(pIdentStr);
    if (len == 3 && strcmp(pIdentStr, "var") == 0) return OPERATOR_PARSE_MODE_VAR_STMT;
    if (len == 4 && strcmp(pIdentStr, "proc") == 0) return OPERATOR_PARSE_MODE_PROC_STMT;
    if (len == 4 && strcmp(pIdentStr, "type") == 0) return OPERATOR_PARSE_MODE_TYPE_STMT;
    return OPERATOR_PARSE_MODE_NIL;
}

AST_ELEM_GET_LITERAL_FUNCTION(binary_operator, operator, out_pOperator) AST_ELEM_GET_LITERAL_FUNCTION_IMPL(AST_NODE_KIND_BINARY_OPER, 0, out_pOperator);
AST_ELEM_GET_FUNCTION(binary_operator, left_operand, out_aeLeftOperand) AST_ELEM_GET_FUNCTION_IMPL(AST_NODE_KIND_BINARY_OPER, 1, out_aeLeftOperand);
AST_ELEM_GET_FUNCTION(binary_operator, right_operand, out_aeRightOperand) AST_ELEM_GET_FUNCTION_IMPL(AST_NODE_KIND_BINARY_OPER, 2, out_aeRightOperand);

AST_ELEM_GET_LITERAL_FUNCTION(unary_operator, operator, out_pOperator) AST_ELEM_GET_LITERAL_FUNCTION_IMPL(AST_NODE_KIND_BINARY_OPER, 0, out_pOperator);
AST_ELEM_GET_FUNCTION(unary_operator, left_operand, out_aeOperand) AST_ELEM_GET_FUNCTION_IMPL(AST_NODE_KIND_BINARY_OPER, 1, out_aeOperand);

AST_ELEM_GET_LITERAL_FUNCTION(var_decl_stmt, var_name, out_pVarName) AST_ELEM_GET_LITERAL_FUNCTION_IMPL(AST_NODE_KIND_VAR_DECL_STMT, 1, out_pVarName);
AST_ELEM_GET_FUNCTION(var_decl_stmt, var_initializer, out_aeInitializer) AST_ELEM_GET_FUNCTION_IMPL(AST_NODE_KIND_VAR_DECL_STMT, 2, out_aeInitializer);

char eval_stack_pop_operator(struct vector* vEvalStack, struct vector* vSyntaxErrors, struct token* tOperatorToken, char bIsUnary, struct ast_node** out_anNode) {
    struct ast_elem* right = 0;
    struct ast_elem* left = 0;
    if (vEvalStack->uLength == 0) {
        INSTANCE_SYNTAX_ERROR_CONTEXT(context, syntax_error_missing_right_hand_operand_context);
        context->tToken = tOperatorToken;
        REGISTER_SYNTAX_ERROR(vSyntaxErrors, error, SYNTAX_ERROR_MISSING_RIGHT_HAND_OPERAND, context);
    } else {
        char ePopRight = vector_pop(vEvalStack, (void*)&right);
        if (ePopRight != VECTOR_SUCCESS) return ePopRight;
        
        if (!bIsUnary) {
            char ePopLeft = vector_pop(vEvalStack, (void*)&left);
            if (ePopLeft != VECTOR_SUCCESS) return ePopLeft;
        }
    }

    struct ast_node* operatorNode = 0;
    char eNewNode = new_ast_node(&operatorNode);
    if (eNewNode != AST_NODE_SUCCESS) return eNewNode;
    char eInitNode = init_ast_node(operatorNode, bIsUnary ? AST_NODE_KIND_UNARY_OPER : AST_NODE_KIND_BINARY_OPER, bIsUnary ? 2 : 3);
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
    if (!bIsUnary && left != 0) {
        char eReplaceLeftOperand = replace_empty_node(operatorNode, left, 1);
        if (eReplaceLeftOperand != AST_NODE_SUCCESS) {
            free(operatorNode);
            free(operatorLiteral);
            return eReplaceLeftOperand;
        }
    }
    if (right != 0) {
        char eReplaceRightOperand = replace_empty_node(operatorNode, right, bIsUnary ? 1 : 2);
        if (eReplaceRightOperand != AST_NODE_SUCCESS) {
            free(operatorNode);
            free(operatorLiteral);
            return eReplaceRightOperand;
        }
    }

    vector_append(vEvalStack, (void*)&operatorNode);

    if (bIsUnary && !can_operator_be_unary(tOperatorToken)) {
        INSTANCE_SYNTAX_ERROR_CONTEXT(context, syntax_error_invalid_unary_operator_context);
        context->tToken = tOperatorToken;
        REGISTER_SYNTAX_ERROR(vSyntaxErrors, error, SYNTAX_ERROR_INVALID_UNARY_OPERATOR, context);
    }

    *out_anNode = operatorNode;
    return AST_NODE_SUCCESS;
}

char eval_stack_pop_var_stmt(struct vector* vEvalStack, struct vector* vSyntaxErrors, struct token* tVarToken, struct ast_node** out_anNode) {
    struct ast_elem* right = 0;
    if (vEvalStack->uLength != 0) {
        char ePopRight = vector_pop(vEvalStack, (void*)&right);
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
        REGISTER_SYNTAX_ERROR(vSyntaxErrors, error, SYNTAX_ERROR_VAR_STMT_EXPECTED_ASSIGNMENT, context);
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
        REGISTER_SYNTAX_ERROR(vSyntaxErrors, error, SYNTAX_ERROR_VAR_STMT_EXPECTED_IDENTIFIER, context);
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

    vector_append(vEvalStack, (void*)&varDeclStmtNode);
    *out_anNode = varDeclStmtNode;

    return AST_NODE_SUCCESS;
}

char pop_greater_precedence(char iPrecedence, struct vector* vOperatorStack, struct vector* vEvalStack, struct vector* vSyntaxErrors) {
    while (vOperatorStack->uLength > 0) { // shunting-yard, we'll pop until this token precedence is greater
        struct operator_pending_pop lastOperatorPending;
        char eLastOp = vector_at(vOperatorStack, vOperatorStack->uLength - 1, (void*)&lastOperatorPending);
        if (eLastOp != VECTOR_SUCCESS) return AST_NODE_FAIL;

        char p = get_operator_precedence(lastOperatorPending.tToken, lastOperatorPending.iOperatorParseMode);

        if (iPrecedence > p) break;
        char ePop = vector_pop(vOperatorStack, 0);
        if (ePop != VECTOR_SUCCESS) return ePop;

        struct ast_node* operatorNode;
        char eStackPop = AST_NODE_FAIL;
        switch (lastOperatorPending.iOperatorParseMode) {
        case OPERATOR_PARSE_MODE_BINARY:
        case OPERATOR_PARSE_MODE_UNARY:
            eStackPop = eval_stack_pop_operator(vEvalStack, vSyntaxErrors, lastOperatorPending.tToken, lastOperatorPending.iOperatorParseMode == OPERATOR_PARSE_MODE_UNARY, &operatorNode);
            break;
        case OPERATOR_PARSE_MODE_VAR_STMT:
            eStackPop = eval_stack_pop_var_stmt(vEvalStack, vSyntaxErrors, lastOperatorPending.tToken, &operatorNode);
            break;
        case OPERATOR_PARSE_MODE_PROC_STMT:
            break;
        case OPERATOR_PARSE_MODE_TYPE_STMT:
            break;
        }
        if (eStackPop != AST_NODE_SUCCESS) return eStackPop;
    }
    return AST_NODE_SUCCESS;
}

char flush_to_expression_list(struct vector* vExpressionList, struct vector* vOperatorStack, struct vector* vEvalStack) {
    char eConcat = vector_append_concat(vExpressionList, vEvalStack);
    if (eConcat != VECTOR_SUCCESS) return eConcat;
    char eClear1 = vector_clear(vOperatorStack);
    if (eClear1 != VECTOR_SUCCESS) return eClear1;
    char eClear2 = vector_clear(vEvalStack);
    if (eClear2 != VECTOR_SUCCESS) return eClear2;
    return AST_NODE_SUCCESS;
}

char build_stmt_list_node(struct token** ptTokens, struct vector* vSyntaxErrors, unsigned int uNumTokens, struct ast_node** out_anStmtListNode) {
    struct vector expressionList = create_vector();
    char eInit = init_vector(&expressionList, 512, sizeof(struct ast_elem*));
    if (eInit != VECTOR_SUCCESS) return AST_NODE_FAIL;
    struct vector operatorStack = create_vector();
    char eInit2 = init_vector(&operatorStack, 512, sizeof(struct operator_pending_pop));
    if (eInit2 != VECTOR_SUCCESS) return AST_NODE_FAIL;
    struct vector evalStack = create_vector();
    char eInit3 = init_vector(&evalStack, 512, sizeof(struct ast_elem*));
    if (eInit3 != VECTOR_SUCCESS) {
        deinit_vector(&operatorStack);
        return AST_NODE_FAIL;
    }

    char lastTransformedTokenValidOperand = 0;
    for (int i = 0; i < uNumTokens; i++) {
        struct token* token = ptTokens[i];
        if (token->iKind == TOKEN_KIND_SEPARATOR) {
            if (operatorStack.uLength > 0) {
                char ePop = pop_greater_precedence(0, &operatorStack, &evalStack, vSyntaxErrors);
                if (ePop != AST_NODE_SUCCESS) return ePop;
            }

            if (evalStack.uLength > 0) {
                char eFlush = flush_to_expression_list(&expressionList, &operatorStack, &evalStack);
                if (eFlush != AST_NODE_SUCCESS) return eFlush;
            }
            continue;
        }
        if (token->iKind == TOKEN_KIND_IDENT) {
            char parseMode = get_keyword_operator_parse_mode(token->pContent);
            if (parseMode != OPERATOR_PARSE_MODE_NIL) {
                if (operatorStack.uLength > 0) {
                    char ePop = pop_greater_precedence(0, &operatorStack, &evalStack, vSyntaxErrors);
                    if (ePop != AST_NODE_SUCCESS) return ePop;
                }

                if (evalStack.uLength > 0) {
                    char eFlush = flush_to_expression_list(&expressionList, &operatorStack, &evalStack);
                    if (eFlush != AST_NODE_SUCCESS) return eFlush;
                }
                
                struct operator_pending_pop operatorPending;
                operatorPending.tToken = token;
                operatorPending.iOperatorParseMode = parseMode;
                char eAddOp = vector_append(&operatorStack, (void*)&operatorPending);
                if (eAddOp != VECTOR_SUCCESS) return eAddOp;
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

            struct ast_literal* literal = 0;
            char eAllocAst = allocate_ast_literal_from_token(token, &literal);
            if (eAllocAst != AST_NODE_SUCCESS) return eAllocAst;

            lastTransformedTokenValidOperand = 1;
            vector_append(&evalStack, (void*)&literal);
            break;
        case TOKEN_KIND_OPERATOR:
            if (operatorStack.uLength > 0) {
                char p = get_operator_precedence(token, lastTransformedTokenValidOperand);
                char ePop = pop_greater_precedence(p, &operatorStack, &evalStack, vSyntaxErrors);
                if (ePop != AST_NODE_SUCCESS) return ePop;
            }

            struct operator_pending_pop operatorPending;
            operatorPending.tToken = token;
            operatorPending.iOperatorParseMode = lastTransformedTokenValidOperand ? OPERATOR_PARSE_MODE_BINARY : OPERATOR_PARSE_MODE_UNARY;
            char eAddOp = vector_append(&operatorStack, (void*)&operatorPending);
            if (eAddOp != VECTOR_SUCCESS) return eAddOp;
            lastTransformedTokenValidOperand = 0;
            break;
        }
    }

    if (operatorStack.uLength > 0) {
        char ePop = pop_greater_precedence(0, &operatorStack, &evalStack, vSyntaxErrors);
        if (ePop != AST_NODE_SUCCESS) return ePop;
    }

    if (evalStack.uLength > 0) {
        char eFlush = flush_to_expression_list(&expressionList, &operatorStack, &evalStack);
        if (eFlush != AST_NODE_SUCCESS) return eFlush;
    }

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

    deinit_vector(&operatorStack);
    deinit_vector(&evalStack);
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
        printf("AST LITERAL: %s (%i)\n", literal->tToken->pContent, literal->iLiteralKind);
        break;
    default:
        struct ast_node* node = (struct ast_node*)anRootElem;
        printf("AST NODE (%i) (%i %s)\n", anRootElem->iKind, node->uNumSons, node->uNumSons == 1 ? "son" : "sons");
        for (int i = 0; i < node->uNumSons; i++) {
            print_ast_string(node->ppSons[i], indent + 1);
        }
        break;
    }
}