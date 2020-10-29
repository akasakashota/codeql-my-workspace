/**
 * @name Use v-html directive
 * @description コード内でv-html ディレクティブを利用しています。v-html ディレクティブはXSS を引き起こす可能性があります。 ref. https://jp.vuejs.org/v2/guide/security.html
 * @id akasakashota/js/vue/use-v-html
 * @kind path-problem
 * @problem.severity error
 * @precision medium
 * @tags vuejs
 *       security
 *       external/cwe/cwe-079
 *       external/cwe/cwe-116
 */

import javascript
import semmle.javascript.security.dataflow.DomBasedXss
import DataFlow::PathGraph

/**
 * 実態は、`DomBasedXss::VHtmlSourceWrite` とほぼ同じ
 * `expr.regexpMatch("(?i)[a-z0-9_]+") and` のロジックをコメントアウトしたいがために再定義
 * 理由は、そういうコードを入れるかどうかは抜きにして変数にユニコード指定も可能は可能なため
 */
class VHtmlSource extends TaintTracking::AdditionalTaintStep {
  DomBasedXss::VHtmlSink attr;

  VHtmlSource() {
    exists(Vue::Instance instance, string expr |
      attr.getAttr().getRoot() =
        instance.getTemplateElement().(Vue::Template::HtmlElement).getElement() and
      expr = attr.getAttr().getValue() and
      // only support for simple identifier expressions
      // expr.regexpMatch("(?i)[a-z0-9_]+") and
      this = instance.getAPropertyValue(expr)
    )
  }

  override predicate step(DataFlow::Node pred, DataFlow::Node succ) {
    pred = this and succ = attr
  }
}

class Configuration extends TaintTracking::Configuration {
  Configuration() { this = "UseVHtml" }

  override predicate isSource(DataFlow::Node source) {
    exists(
      DataFlow::ValueNode n, VHtmlSource w |
      // v-html の値に同じコード内で固定化された値（Literal）が入ることは許容
      // （コード内に悪意のあるHTML が含まれることを想定しないため）
      not n.getAPredecessor*().asExpr() instanceof Literal and
      n.getASuccessor*() = w and

      if(exists(n.getALocalSource()))
      then source = n.getALocalSource()
      else source = n
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(DomBasedXss::VHtmlSink s| sink = s)
  }
}

from Configuration cfg, DataFlow::SourcePathNode source, DataFlow::SinkPathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Potential XSS vulnerability due to use v-html directive."