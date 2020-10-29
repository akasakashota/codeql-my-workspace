<template>
    <p v-html="constInt"/>
    <p v-html="constStr"/>
    <p v-html="constStr2"/>
    <p v-html="定数"/>
    <p v-html="constComp"/>
    <p v-html="constComp2"/>
    <p v-html="funcConst"/>
    <p v-html="helloConst"/>
</template>
<script>
  const v = "hoge";
  let v2 = v;
  var comp = null || "fuga";
  const unusedVar = window.location.hash

  export default {
    data: function() {
      return {
        constInt: 1,
        constStr: "hoge",
        constStr2: v,
        "定数": v2,
        constComp: null || "fuga",
        constComp2: comp,
        funcConst: (()=>{return "hoge";})(),
      }
    },
    computed: {
      helloConst() {
        return "hoge";
      }
    }
  }
</script>
<style>
</style>