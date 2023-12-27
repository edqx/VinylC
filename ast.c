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
    }
}

SYNTAX_ERROR_PRINT_FUNCTION(invalid_unary_operator, syntax_error_invalid_unary_operator_context) {
    printf("\x1b[91m[ERROR]: Invalid unary operator: %s at %i-%i\x1b[0m\n", pContext->tToken->pContent, pContext->tToken->fiirFileRange.uStartIdx, pContext->tToken->fiirFileRange.uEndIdx);
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
    return alSelf->pContent == 0 ? AST_NODE_SUCCESS : AST_NODE_FAIL;
}

char init_ast_literal(struct ast_literal* alSelf, char iLiteralKind, const char* pContent) {
    if (assert_ast_literal_not_initialized(alSelf) == AST_NODE_FAIL) return AST_NODE_ALREADY_INITIALIZED;
    alSelf->iKind = AST_NODE_KIND_LITERAL;
    alSelf->iLiteralKind = iLiteralKind;
    unsigned int contentLen = strlen(pContent);
    alSelf->pContent = (const char*)malloc(contentLen + 1);
    if (alSelf->pContent == 0) return AST_NODE_FAIL;
    memcpy((char*)alSelf->pContent, pContent, contentLen);
    ((char*)alSelf->pContent)[contentLen] = '\0';
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
    char eInit = init_ast_literal(*out_alLiteral, literalTokenKind, tToken->pContent);
    if (eInit != AST_NODE_SUCCESS) {
        free(*out_alLiteral);
        return eInit;
    }
    return AST_NODE_SUCCESS;
}

char can_operator_be_unary(struct token* tToken) {
    return tToken->pContent[0] == '+' || (tToken->pContent[0] == '-' && tToken->pContent[1] == '\0');
}

char get_operator_precedence(struct token* tToken, char bIsUnary) {
    switch (tToken->pContent[0]) {
        case '.':
            return AST_OPERATOR_PRECEDENCE_ACCESS;
        case '-':
            switch (tToken->pContent[1]) {
            case '\0': // "-"
                return bIsUnary ? AST_OPERATOR_PRECEDENCE_UNARY_PREF : AST_OPERATOR_PRECEDENCE_ADD;
            case '>': // "->"
                return AST_OPERATOR_PRECEDENCE_ACCESS;
            }
            break;
        case '=':
            switch (tToken->pContent[1]) {
            case '\0': // "="
                return AST_OPERATOR_PRECEDENCE_ASSIGN;
            case '=': // "=="
                return AST_OPERATOR_PRECEDENCE_EQUAL;
            }
            break;
        case '>':
            switch (tToken->pContent[1]) {
            case '=': // >=
                return AST_OPERATOR_PRECEDENCE_COMPARE;
            }
            break;
        case '<':
            switch (tToken->pContent[1]) {
            case '=': // <=
                return AST_OPERATOR_PRECEDENCE_COMPARE;
            }
            break;
        case '+':
            return AST_OPERATOR_PRECEDENCE_ADD;
        case '*':
            return AST_OPERATOR_PRECEDENCE_MUL;
        case '/':
            return AST_OPERATOR_PRECEDENCE_MUL;
        case '%':
            return AST_OPERATOR_PRECEDENCE_MUL;
        case '|':
            switch (tToken->pContent[1]) {
            case '|': // "||"
                return AST_OPERATOR_PRECEDENCE_LOGIC_OR;
            }
            break;
        case '&':
            switch (tToken->pContent[1]) {
            case '\0': // "&"
                return AST_OPERATOR_PRECEDENCE_CONCAT;
            case '&': // "&&"
                return AST_OPERATOR_PRECEDENCE_LOGIC_AND;
            }
            break;
    }
    return 0;
}

char eval_stack_pop_operator(struct vector* vEvalStack, struct vector* vSyntaxErrors, struct operator_pending_pop tOperatorPending, struct ast_node** out_anNode) {
    struct ast_elem* right = 0;
    struct ast_elem* left = 0;
    char ePopRight = vector_pop(vEvalStack, (void*)&right);
    if (ePopRight != VECTOR_SUCCESS) return ePopRight;
    if (!tOperatorPending.bIsUnary) {
        char ePopLeft = vector_pop(vEvalStack, (void*)&left);
        if (ePopLeft != VECTOR_SUCCESS) return ePopLeft;
    }

    struct ast_node* operatorNode = 0;
    char eNewNode = new_ast_node(&operatorNode);
    if (eNewNode != AST_NODE_SUCCESS) return eNewNode;
    char eInitNode = init_ast_node(operatorNode, AST_NODE_KIND_BINARY_OPER, tOperatorPending.bIsUnary ? 2 : 3);
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
    char eInitliteral = init_ast_literal(operatorLiteral, AST_LITERAL_KIND_OPER, tOperatorPending.tOperator->pContent);
    if (eInitliteral != AST_NODE_SUCCESS) {
        free(operatorNode);
        free(operatorLiteral);
        return eInitliteral;
    }

    char r1 = replace_empty_node(operatorNode, (struct ast_elem*)operatorLiteral, 0);
    if (r1 != AST_NODE_SUCCESS) {
        free(operatorNode);
        free(operatorLiteral);
        return r1;
    }
    if (!tOperatorPending.bIsUnary) {
        char r2 = replace_empty_node(operatorNode, left, 1);
        if (r2 != AST_NODE_SUCCESS) {
            free(operatorNode);
            free(operatorLiteral);
            return r2;
        }
    }
    char r3 = replace_empty_node(operatorNode, right, tOperatorPending.bIsUnary ? 1 : 2);
    if (r3 != AST_NODE_SUCCESS) {
        free(operatorNode);
        free(operatorLiteral);
        return r3;
    }

    vector_append(vEvalStack, (void*)&operatorNode);

    if (tOperatorPending.bIsUnary && !can_operator_be_unary(tOperatorPending.tOperator)) {
        INSTANCE_SYNTAX_ERROR_CONTEXT(context, syntax_error_invalid_unary_operator_context);
        context->tToken = tOperatorPending.tOperator;
        REGISTER_SYNTAX_ERROR(vSyntaxErrors, error, SYNTAX_ERROR_INVALID_UNARY_OPERATOR, context);
    }

    *out_anNode = operatorNode;
    return AST_NODE_SUCCESS;
}

char pop_greater_precedence(char iPrecedence, struct vector* vOperatorStack, struct vector* vEvalStack, struct vector* vSyntaxErrors) {
    while (vOperatorStack->uLength > 0) { // shunting-yard, we'll pop until this token precedence is greater
        struct operator_pending_pop lastOperatorPending;
        char eLastOp = vector_at(vOperatorStack, vOperatorStack->uLength - 1, (void*)&lastOperatorPending);
        if (eLastOp != VECTOR_SUCCESS) return AST_NODE_FAIL;

        char p = get_operator_precedence(lastOperatorPending.tOperator, lastOperatorPending.bIsUnary);

        if (iPrecedence > p) break;
        char ePop = vector_pop(vOperatorStack, 0);
        if (ePop != VECTOR_SUCCESS) return ePop;

        struct ast_node* operatorNode;
        char eStackPop = eval_stack_pop_operator(vEvalStack, vSyntaxErrors, lastOperatorPending, &operatorNode);
        if (eStackPop != AST_NODE_SUCCESS) return eStackPop;
    }
    return AST_NODE_SUCCESS;
}

char build_stmt_list_node(struct token** ptTokens, struct vector* vSyntaxErrors, unsigned int uNumTokens, struct ast_node** out_anStmtListNode) {
    struct vector operatorStack = create_vector();
    char eInit = init_vector(&operatorStack, 512, sizeof(struct operator_pending_pop));
    if (eInit != VECTOR_SUCCESS) return AST_NODE_FAIL;
    struct vector evalStack = create_vector();
    char eInit2 = init_vector(&evalStack, 512, sizeof(struct ast_elem*));
    if (eInit2 != VECTOR_SUCCESS) {
        deinit_vector(&operatorStack);
        return AST_NODE_FAIL;
    }

    struct token* lastTransformedToken = 0;
    for (int i = 0; i < uNumTokens; i++) {
        struct token* token = ptTokens[i];
        if (token->iKind == TOKEN_KIND_NUMBER || token->iKind == TOKEN_KIND_STR || token->iKind == TOKEN_KIND_IDENT) {
            struct ast_literal* literal = 0;
            char eAllocAst = allocate_ast_literal_from_token(token, &literal);
            if (eAllocAst != AST_NODE_SUCCESS) return eAllocAst;

            lastTransformedToken = token;
            vector_append(&evalStack, (void*)&literal);
        } else if (token->iKind == TOKEN_KIND_OPERATOR) {
            char isUnary = lastTransformedToken == 0
                || lastTransformedToken->iKind == TOKEN_KIND_OPERATOR
                || lastTransformedToken->iKind == TOKEN_KIND_SEPARATOR;
            if (operatorStack.uLength > 0) {
                char p = get_operator_precedence(token, isUnary);
                char ePop = pop_greater_precedence(p, &operatorStack, &evalStack, vSyntaxErrors);
                if (ePop != AST_NODE_SUCCESS) return ePop;
            }

            struct operator_pending_pop operatorPending;
            operatorPending.tOperator = token;
            operatorPending.bIsUnary = isUnary;
            char eAddOp = vector_append(&operatorStack, (void*)&operatorPending);
            if (eAddOp != VECTOR_SUCCESS) return eAddOp;
            lastTransformedToken = token;
        }
    }

    if (operatorStack.uLength > 0) {
        char ePop = pop_greater_precedence(0, &operatorStack, &evalStack, vSyntaxErrors);
        if (ePop != AST_NODE_SUCCESS) return ePop;
    }

    char eNewNode = new_ast_node(out_anStmtListNode);
    if (eNewNode != AST_NODE_SUCCESS) return eNewNode;
    char eInitNode = init_ast_node(*out_anStmtListNode, AST_NODE_KIND_STMT_LIST, evalStack.uLength);
    if (eInitNode != AST_NODE_SUCCESS) {
        free(*out_anStmtListNode);
        return eInitNode;
    }
    for (int i = 0; i < evalStack.uLength; i++) {
        struct ast_elem* evalElem;
        vector_at(&evalStack, i, (void*)&evalElem);
        char eReplace = replace_empty_node(*out_anStmtListNode, evalElem, i);
        if (eReplace != AST_NODE_SUCCESS) return eReplace;
    }

    deinit_vector(&operatorStack);
    deinit_vector(&evalStack);
}

char build_variable_assignment_node(struct token** ptTokens, unsigned int uNumTokens, struct ast_node* out_anNode) {
    
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
    case AST_NODE_KIND_LITERAL:
        struct ast_literal* literal = (struct ast_literal*)anRootElem;
        printf("AST LITERAL: %s (%i)\n", literal->pContent, literal->iLiteralKind);
        break;
    default:
        struct ast_node* node = (struct ast_node*)anRootElem;
        printf("AST NODE (%i) (%i %s)\n", anRootElem->iKind, node->uNumSons, node->uNumSons == 1 ? "child" : "children");
        for (int i = 0; i < node->uNumSons; i++) {
            print_ast_string(node->ppSons[i], indent + 1);
        }
        break;
    }
}