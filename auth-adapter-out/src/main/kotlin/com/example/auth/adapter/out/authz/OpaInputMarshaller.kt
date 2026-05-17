package com.example.auth.adapter.out.authz

import com.example.auth.application.authz.PolicyDecisionRequest
import com.example.auth.application.authz.PolicyDecisionResult
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ObjectNode
import java.util.LinkedHashMap

/**
 * OPA REST API (`POST /v1/data/<policy>/<rule>`) 입력 / 출력 매핑.
 *
 * OPA wire 형식 — request body: `{"input": <user-defined json>}`,
 * response body: `{"result": <evaluated value>}`.
 *
 * Rego 측에서 `input.subject.tenantId`, `input.resource.ownerUser` 처럼
 * 접근하므로 nested object 형태 그대로 직렬화합니다. UUID 는 Rego 의 string 비교에 그대로
 * 들어가도록 `asString()` 으로 변환.
 */
object OpaInputMarshaller {

    @JvmStatic
    fun toInput(om: ObjectMapper, request: PolicyDecisionRequest): ObjectNode {
        val root = om.createObjectNode()
        val input = root.putObject("input")

        // subject
        val subject = input.putObject("subject")
        subject.put("tenantId", request.subject.tenantId.asString())
        subject.put("userId", request.subject.userId.asString())
        val rolesArr = subject.putArray("roles")
        request.subject.roles.forEach { rolesArr.add(it) }
        val permsArr = subject.putArray("permissions")
        request.subject.permissions.forEach { permsArr.add(it) }
        if (request.subject.attributes.isNotEmpty()) {
            subject.set<JsonNode>("attributes", om.valueToTree(request.subject.attributes))
        }

        // action
        input.put("action", request.action)

        // resource (nullable)
        val resource = request.resource
        if (resource != null) {
            val resourceNode = input.putObject("resource")
            resourceNode.put("type", resource.type)
            resource.ownerTenant?.let { resourceNode.put("ownerTenant", it.asString()) }
            resource.ownerUser?.let { resourceNode.put("ownerUser", it.asString()) }
            if (resource.attributes.isNotEmpty()) {
                resourceNode.set<JsonNode>("attributes", om.valueToTree(resource.attributes))
            }
        }

        // context — 자유 형식 map. ip / userAgent / time 등이 들어옴.
        if (request.context.isNotEmpty()) {
            input.set<JsonNode>("context", om.valueToTree(request.context))
        }
        return root
    }

    /**
     * OPA 응답 파싱. 두 가지 응답 형태를 모두 처리:
     *
     * 1. document 단위 평가 (`/v1/data/auth/session/revoke`) — 응답 안에 allow / reasons 둘
     *    다 들어옴.
     * 2. rule 단위 평가 (`/v1/data/auth/session/revoke/allow`) — 응답이 단순 boolean.
     */
    @JvmStatic
    fun parseResponse(body: JsonNode?): PolicyDecisionResult {
        if (body == null) {
            return PolicyDecisionResult.denied("opa_empty_response")
        }
        val result = body.get("result")
        if (result == null || result.isNull) {
            // OPA 는 정책이 정의되지 않으면 result 없이 응답하기도 함. fail-closed.
            return PolicyDecisionResult.denied("opa_no_result")
        }

        if (result.isBoolean) {
            return if (result.asBoolean()) {
                PolicyDecisionResult.allowed()
            } else {
                PolicyDecisionResult.denied("opa_disallow")
            }
        }
        if (result.isObject) {
            val allow = result.has("allow") && result.get("allow").asBoolean(false)
            val reasons = ArrayList<String>()
            val reasonsNode = result.get("reasons")
            if (reasonsNode != null && reasonsNode.isArray) {
                reasonsNode.forEach { reasons.add(it.asText()) }
            }
            val obligations = LinkedHashMap<String, Any?>()
            val obligationsNode = result.get("obligations")
            if (obligationsNode != null && obligationsNode.isObject) {
                obligationsNode.fieldNames().forEachRemaining { f ->
                    obligations[f] = jsonNodeToObject(obligationsNode.get(f))
                }
            }
            if (allow) {
                return PolicyDecisionResult(true, reasons, obligations)
            }
            if (reasons.isEmpty()) reasons.add("opa_disallow")
            return PolicyDecisionResult(false, reasons, obligations)
        }
        return PolicyDecisionResult.denied("opa_unexpected_result_shape")
    }

    private fun jsonNodeToObject(node: JsonNode?): Any? {
        if (node == null || node.isNull) return null
        if (node.isTextual) return node.asText()
        if (node.isBoolean) return node.asBoolean()
        if (node.isInt || node.isLong) return node.asLong()
        if (node.isDouble || node.isFloat) return node.asDouble()
        return node.toString()
    }
}
