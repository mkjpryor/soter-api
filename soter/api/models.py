"""
Module containing models returned by the API.
"""

from collections.abc import MutableSet

from sortedcontainers import SortedDict

from pydantic import BaseModel, validator, constr, conset

from ..scanner.models import Severity


class Issue(BaseModel):
    """
    Base class for all issue types.
    """
    #: The kind of the issue
    kind: constr(min_length = 1) = None
    #: The title of the issue
    title: constr(min_length = 1)
    #: The severity of the issue
    severity: Severity
    #: The set of scanners that reported the issue
    reported_by: conset(constr(min_length = 1), min_items = 1)

    @validator('kind', pre = True, always = True)
    def default_kind(cls, kind):
        # The kind is the name of the issue class
        return cls.__name__

    @property
    def aggregation_key(self):
        """
        The aggregation key for the issue.
        """
        # By default, aggregate all issues with the same kind and title.
        return (self.kind, self.title)

    def merge(self, other):
        """
        Merge two issues into one.
        """
        # If the aggregation keys match, the issues can be aggregated
        if self.aggregation_key != other.aggregation_key:
            raise ValueError('issues are not compatible for aggregation')
        # For the severity of the aggregated issue, use the max of the two issues
        # The exception is if one of the severities is UNKNOWN, in which case we use the other one
        if self.severity == Severity.UNKNOWN:
            severity = other.severity
        elif other.severity == Severity.UNKNOWN:
            severity = self.severity
        else:
            severity = max(self.severity, other.severity)
        return self.copy(
            update = dict(
                severity = severity,
                # Combine the scanners
                reported_by = self.reported_by.union(other.reported_by)
            )
        )


class Error(Issue):
    """
    Issue type that represents an error in the system.
    """
    #: The severity of the error
    # An error is flagged as unknown because it prevents us from knowing if there is a problem or not
    severity: Severity = Severity.UNKNOWN
    #: The detail for the error
    detail: constr(min_length = 1)

    @property
    def aggregation_key(self):
        """
        The aggregation key for the issue.
        """
        # Include the error detail in the aggregation key
        return super().aggregation_key + (self.detail, )


class ValueSortedDict(SortedDict):
    """
    Class for a dictionary that is sorted by the values.
    """
    def __init__(self, *args, **kwargs):
        if args and callable(args[0]):
            key = args[0]
            args = args[1:]
        else:
            key = lambda v: v
        # The key function recieves the value
        super().__init__(lambda k: key(self[k]), *args, **kwargs)

    def __setitem__(self, key, value):
        # Because the key function uses the value, it must be in self
        # before we attempt to add the key to the sorted list
        if key in self:
            self._list_remove(key)
        dict.__setitem__(self, key, value)
        self._list_add(key)

    _setitem = __setitem__


class IssueSet(MutableSet):
    """
    Class for a set of issues.

    The added issues are automatically aggregated and sorted by severity.
    """
    @classmethod
    def __get_validators__(cls):
        # This is required for the type to be used in Pydantic models
        yield cls

    def __init__(self, issues = None):
        # Under the hood, we use a dictionary of aggregation key -> aggregated issue
        # This dictionary is sorted by the severity of the aggregated issue
        self._issues = ValueSortedDict(lambda i: i.severity)
        # Insert each issue from the given iterable
        if issues:
            for issue in issues:
                self.add(issue)

    def __contains__(self, item):
        # Return true if the set contains an item with the same aggregation key
        if isinstance(item, Issue):
            return item.aggregation_key in self._issues
        else:
            return False

    def __iter__(self):
        # Iterate the values of the sorted dict in reverse order (highest first)
        return reversed(self._issues.values())

    def __len__(self):
        return len(self._issues)

    def add(self, value):
        # Only permit issues to be added to the set
        if not isinstance(value, Issue):
            raise ValueError('value is not an issue')
        # Check if we need to aggregate with an existing issue
        aggregation_key = value.aggregation_key
        try:
            existing = self._issues.pop(aggregation_key)
        except KeyError:
            self._issues[aggregation_key] = value
        else:
            self._issues[aggregation_key] = existing.merge(value)

    def discard(self, value):
        raise NotImplementedError


class Report(BaseModel):
    """
    Base class for all report classes.
    """
    #: Set of issues
    issues: IssueSet

    def dict(self, *args, **kwargs):
        # When serializing, ensure that the issues are a list
        result = super().dict(*args, **kwargs)
        if 'issues' in result:
            result.update(issues = list(result['issues']))
        return result
