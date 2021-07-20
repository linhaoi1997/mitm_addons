"""
for graphql view query
"""
import json
import re

from mitmproxy import contentviews
from mitmproxy.contentviews import views
from .auto_select import ViewAuto
from beeprint import pp


def double_space(match_obj):
    return match_obj.group(1) * 2


class ViewGraphqlQuery(contentviews.View):
    """查看graphql的query"""
    name = "GraphqlQuery"
    content_types = ["text/plain"]

    def __call__(self, data, **metadata) -> contentviews.TViewResult:
        query = json.loads(data).get("query")
        query = re.sub("( +)", double_space, query)

        return "graphql query", contentviews.format_text(query)


class ViewGraphqlVariables(contentviews.View):
    """查看graphql的varibales"""
    name = "GraphqlVariables"
    content_types = ["text/plain"]

    def __call__(self, data, **metadata) -> contentviews.TViewResult:
        query = json.loads(data).get("query").split("\n")[0].rstrip(" {")
        variables = pp(json.loads(data).get("variables"), output=False)

        def result():
            yield from contentviews.format_text(query)
            yield from contentviews.format_text("variables: \n")
            yield from contentviews.format_text(variables)

        return "graphql variables", result()


view = ViewGraphqlQuery()
view2 = ViewGraphqlVariables()


def load(l):
    views[0] = ViewAuto()
    contentviews.add(view)
    contentviews.add(view2)


def done():
    contentviews.remove(view)
    contentviews.remove(view2)
