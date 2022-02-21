# [LeetCode]前期刷题合集

# [LeetCode每日一题]1143. 最长公共子序列

## 问题

```
给定两个字符串 text1 和 text2，返回这两个字符串的最长 公共子序列 的长度。如果不存在 公共子序列 ，返回 0 。

一个字符串的 子序列 是指这样一个新的字符串：它是由原字符串在不改变字符的相对顺序的情况下删除某些字符（也可以不删除任何字符）后组成的新字符串。

例如，"ace" 是 "abcde" 的子序列，但 "aec" 不是 "abcde" 的子序列。
两个字符串的 公共子序列 是这两个字符串所共同拥有的子序列。

示例 1：
输入：text1 = "abcde", text2 = "ace" 
输出：3  
解释：最长公共子序列是 "ace" ，它的长度为 3 。
示例 2：
输入：text1 = "abc", text2 = "abc"
输出：3
解释：最长公共子序列是 "abc" ，它的长度为 3 。
示例 3：
输入：text1 = "abc", text2 = "def"
输出：0
解释：两个字符串没有公共子序列，返回 0 。

提示：
1 <= text1.length, text2.length <= 1000
text1 和 text2 仅由小写英文字符组成。
```

简单的动态规划，z大神秒杀的那种，本菜鸡瑟瑟发抖。

## 解题思路

求两个数组或者字符串的最长公共子序列问题，肯定是要用动态规划的。

首先，区分两个概念：**子序列**可以是不连续的；**子数组**（子字符串）需要是连续的；
另外，**动态规划也是有套路的：单个数组或者字符串要用动态规划时，可以把动态规划 dp[i] 定义为 nums[0:i] 中想要求的结果；当两个数组或者字符串要用动态规划时，可以把动态规划定义成两维的 dp[i][j] ，其含义是在 A[0:i] 与 B[0:j] 之间匹配得到的想要的结果。**

### 1.状态定义

比如对于本题而言，可以定义 dp[i][j]表示 text1[0:i-1] 和 text2[0:j-1] 的最长公共子序列。 （注：text1[0:i-1] 表示的是 text1 的 第 0 个元素到第 i - 1 个元素，两端都包含）
之所以 dp[i][j] 的定义不是 text1[0:i] 和 text2[0:j] ，是为了方便当 i = 0 或者 j = 0 的时候，dp[i][j]表示为空字符串和另外一个字符串的匹配，这样 dp[i][j] 可以初始化为 0.

### 2.状态转移方程

知道状态定义之后，我们开始写状态转移方程。

当 text1[i - 1] == text2[j - 1] 时，说明两个子字符串的最后一位相等，所以最长公共子序列又增加了 1，所以 dp[i][j] = dp[i - 1][j - 1] + 1；举个例子，比如对于 ac 和 bc 而言，他们的最长公共子序列的长度等于 a 和 c 的最长公共子序列长度 0 + 1 = 1。
当 text1[i - 1] != text2[j - 1] 时，说明两个子字符串的最后一位不相等，那么此时的状态 dp[i][j] 应该是 dp[i - 1][j] 和 dp[i][j - 1] 的最大值。举个例子，比如对于 ace 和 bc 而言，他们的最长公共子序列的长度等于 ① ace 和 b 的最长公共子序列长度0 与 ② ac 和 bc 的最长公共子序列长度1 的最大值，即 1。
综上状态转移方程为：

dp[i][j] = dp[i - 1][j - 1] + 1dp[i][j]=dp[i−1][j−1]+1, 当 text1[i - 1] == text2[j - 1];text1[i−1]==text2[j−1];
dp[i][j] = max(dp[i - 1][j], dp[i][j - 1])dp[i][j]=max(dp[i−1][j],dp[i][j−1]), 当 text1[i - 1] != text2[j - 1]text1[i−1]!=text2[j−1]

### 3.状态的初始化

初始化就是要看当 i = 0 与 j = 0 时， dp[i][j] 应该取值为多少。

当 i = 0 时，dp[0][j] 表示的是text1中取空字符串 跟text2的最长公共子序列，结果肯定为 0.
当 j = 0 时，dp[i][0] 表示的是text2中取空字符串 跟text1的最长公共子序列，结果肯定为 0.
综上，当 i = 0 或者 j = 0 时，dp[i][j] 初始化为 0.

### 4.遍历方向与范围

由于 dp[i][j] 依赖与 dp[i - 1][j - 1] , dp[i - 1][j], dp[i][j - 1]，所以i和j的遍历顺序肯定是从小到大的。
另外，由于当 ii 和 jj 取值为 0 的时候，dp[i][j] = 0，而 dp 数组本身初始化就是为 0，所以，直接让 i 和 j 从 1 开始遍历。遍历的结束应该是字符串的长度为 len(text1) 和 len(text2)。

### 5.最终返回结果

由于 dp[i][j] 的含义是 text1[0:i-1] 和 text2[0:j-1] 的最长公共子序列。我们最终希望求的是 text1 和 text2 的最长公共子序列。所以需要返回的结果是 i = len(text1) 并且 j = len(text2) 时的 dp[len(text1)][len(text2)]。

## 代码

经过上面的分析，我们可以得到下面的代码。

```
#include<bits/stdc++.h>
using namespace std;
class Solution {
	public:
		int longestCommonSubsequence(string text1, string text2) {
			int m = text1.length(), n = text2.length();
			vector<vector<int>> dp(m + 1, vector<int>(n + 1));
			for (int i = 1; i <= m; i++) {
				char c = text1.at(i - 1);
				for (int j = 1; j <= n; j++) {
					char b = text2.at(j - 1);
					if (c == b) {
						dp[i][j] = dp[i - 1][j - 1] + 1;
					} else {
						dp[i][j] = max(dp[i - 1][j], dp[i][j - 1]);
					}
				}
			}
			cout << dp[m][n] << endl;
			return dp[m][n];
		}
};

int main() {
	Solution s;
	string text1, text2;
	text1 = "abcde", text2 = "ace";
	s.longestCommonSubsequence(text1, text2);
	return 0;
}
```

# [LeetCode每日一题]781. 森林中的兔子

## 问题

```
森林中，每个兔子都有颜色。其中一些兔子（可能是全部）告诉你还有多少其他的兔子和自己有相同的颜色。我们将这些回答放在 answers 数组里。

返回森林中兔子的最少数量。

示例:
输入: answers = [1, 1, 2]
输出: 5
解释:
两只回答了 "1" 的兔子可能有相同的颜色，设为红色。
之后回答了 "2" 的兔子不会是红色，否则他们的回答会相互矛盾。
设回答了 "2" 的兔子为蓝色。
此外，森林中还应有另外 2 只蓝色兔子的回答没有包含在数组中。
因此森林中兔子的最少数量是 5: 3 只回答的和 2 只没有回答的。

输入: answers = [10, 10, 10]
输出: 11

输入: answers = []
输出: 0

说明:
answers 的长度最大为1000。
answers[i] 是在 [0, 999] 范围内的整数。
```

## 解题思路

使用辅助容器num来保存回答的情况

分成两种情况：

### 1.回答为0，直接加一，因为没有别的兔子颜色和你一样！

### 2.回答不为0，为n：

#### 2.1此前没有兔子回答和你一样的数量！兔子总数+(n+1)，并把n放入容器

#### 2.2此前有兔子回答跟你一样的数量了！假设n=3，则为了使兔子数量尽量小，最多使4只回答为3的兔子颜色一样，因此若回答为3的兔子数量达到4只，全部消去，相当于此前没有兔子回答这个数量。若还没有达到4只，放入num容器。

## 代码

```
class Solution {
	public:
		int numRabbits(vector<int>& answers) {
			int sum = 0, n = 0;
			vector<int> num;
			for (unsigned int i = 0; i < answers.size(); i++) {
				n = count(num.begin(), num.end(), answers[i]);
				if (n == 0) {//没有这种数量
					num.push_back(answers[i]);
					sum += answers[i] + 1;
				} else if (answers[i] == 0) { //另有0种相同数量的兔子，直接+1
					sum += 1;
				} else { //有这种数量
					if (n == answers[i]) {
						num.erase(remove(num.begin(), num.end(), n), num.end());
					} else {
						num.push_back(answers[i]);
					}
				}
			}
			return sum;
		}
};
```

另一位大佬的代码，看上去更简洁，是用map容器实现的

```
class Solution {
	public:
		int numRabbits(vector<int>& answers) {
			if (answers.empty()) return 0;
			int res = 0;
			unordered_map<int, int> hash;               //存储<数字， 说了这个数字的兔子数量>
			for (int num : answers) {
				if (!hash.count(num) || hash[num] == 0) { //没有记录或当前数字的兔子数量为0时
					res += num + 1;
					hash[num] ++ ;                      //当前数字的兔子数量自增1
				} else if (hash.count(num))             //已有记录就继续自增
					hash[num] ++ ;
				if (hash[num] == num + 1)           //当兔子数量等于数字时，表示达到该种颜色所能代表的数量上限
					hash[num] = 0;                  //重置兔子数量为零，若再遇到相同数字，需要开另一种颜色来存
			}
			return res;
		}
};
```

# [LeetCode每日一题]88. 合并两个有序数组

## 问题

```
给你两个有序整数数组 nums1 和 nums2，请你将 nums2 合并到 nums1 中，使 nums1 成为一个有序数组。

初始化 nums1 和 nums2 的元素数量分别为 m 和 n 。你可以假设 nums1 的空间大小等于 m + n，这样它就有足够的空间保存来自 nums2 的元素。

 

示例 1：

输入：nums1 = [1,2,3,0,0,0], m = 3, nums2 = [2,5,6], n = 3
输出：[1,2,2,3,5,6]
示例 2：

输入：nums1 = [1], m = 1, nums2 = [], n = 0
输出：[1]
 

提示：

nums1.length == m + n
nums2.length == n
0 <= m, n <= 200
1 <= m + n <= 200
-10的九次方 <= nums1[i], nums2[i] <= 10的九次方
```

## 代码

没啥好说的

```
class Solution {
	public:
		void merge(vector<int>& nums1, int m, vector<int>& nums2, int n) {
			for (int i = 0; i < n; i++) {
				nums1[i + m] = nums2[i];
			}
			sort(nums1.begin(), nums1.end());
		}
};
```

前面没有利用数组已经被排序的性质。为了利用这一性质，我们可以使用双指针方法。这一方法将两个数组看作队列，每次从两个数组头部取出比较小的数字放到结果中

```
class Solution {
public:
    void merge(vector<int>& nums1, int m, vector<int>& nums2, int n) {
        int p1 = 0, p2 = 0;
        int sorted[m + n];
        int cur;
        while (p1 < m || p2 < n) {
            if (p1 == m) {
                cur = nums2[p2++];
            } else if (p2 == n) {
                cur = nums1[p1++];
            } else if (nums1[p1] < nums2[p2]) {
                cur = nums1[p1++];
            } else {
                cur = nums2[p2++];
            }
            sorted[p1 + p2 - 1] = cur;
        }
        for (int i = 0; i != m + n; ++i) {
            nums1[i] = sorted[i];
        }
    }
};
```

还有一种方法:方法二中，之所以要使用临时变量，是因为如果直接合并到数组nums1中，num1中的元素可能会在取出之前被覆盖。那么如何直接避免覆盖nums1中的元素呢？观察可知,nums1的后半部分是空的，可以直接覆盖而不会影响结果。因此可以指针设置为从后向前遍历，每次取两者之中的较大者放进nums1的最后面。

```
class Solution {
public:
    void merge(vector<int>& nums1, int m, vector<int>& nums2, int n) {
        int p1 = m - 1, p2 = n - 1;
        int tail = m + n - 1;
        int cur;
        while (p1 >= 0 || p2 >= 0) {
            if (p1 == -1) {
                cur = nums2[p2--];
            } else if (p2 == -1) {
                cur = nums1[p1--];
            } else if (nums1[p1] > nums2[p2]) {
                cur = nums1[p1--];
            } else {
                cur = nums2[p2--];
            }
            nums1[tail--] = cur;
        }
    }
};
```

# [LeetCode每日一题]80. 删除有序数组中的重复项 II

## 问题

```
给你一个有序数组 nums ，请你 原地 删除重复出现的元素，使每个元素 最多出现两次 ，返回删除后数组的新长度。

不要使用额外的数组空间，你必须在 原地 修改输入数组 并在使用 O(1) 额外空间的条件下完成。

 

说明：

为什么返回数值是整数，但输出的答案是数组呢？

请注意，输入数组是以「引用」方式传递的，这意味着在函数里修改输入数组对于调用者是可见的。

你可以想象内部操作如下:

// nums 是以“引用”方式传递的。也就是说，不对实参做任何拷贝
int len = removeDuplicates(nums);

// 在函数里修改输入数组对于调用者是可见的。
// 根据你的函数返回的长度, 它会打印出数组中 该长度范围内 的所有元素。
for (int i = 0; i < len; i++) {
    print(nums[i]);
}
 

示例 1：

输入：nums = [1,1,1,2,2,3]
输出：5, nums = [1,1,2,2,3]
解释：函数应返回新长度 length = 5, 并且原数组的前五个元素被修改为 1, 1, 2, 2, 3 。 不需要考虑数组中超出新长度后面的元素。
示例 2：

输入：nums = [0,0,1,1,1,1,2,3,3]
输出：7, nums = [0,0,1,1,2,3,3]
解释：函数应返回新长度 length = 7, 并且原数组的前五个元素被修改为 0, 0, 1, 1, 2, 3, 3 。 不需要考虑数组中超出新长度后面的元素。
 

提示：

1 <= nums.length <= 3 * 10的4次方
-10的4次方 <= nums[i] <= 10的4次方
nums 已按升序排列
```

## 思路

由于要求使用**原地算法**（一个原地算法（in-place algorithm）是一种使用小的，**固定数量的额外之空间**来转换资料的算法。当算法执行时，输入的资料通常会被要输出的部份**覆盖**掉，个人认为简而言之就是采用固定数量的中间变量来使后面的元素覆盖前面的元素），就应该想到用**双指针**（原地修改，那么肯定就需要一个指针指向当前即将放置元素的位置，需要另外一个指针向后遍历所有元素），尤其是给定的数组是有序的，这就更应该想到用双指针了（双指针能够有效发挥出数组有序的优势），在这里将双指针分为快指针和慢指针，刚开始这两者往往相等。**慢指针在满足某种条件的时候停下**（这里的条件就是当前下标为k的元素和下标为k-2的元素相等）**，与快指针拉开差距，于是它指向要被覆盖**（或者说被修改）**的地方，而快指针不断向前，找到满足某种条件的元素**（这里的条件是找到的元素与下标为k-2的元素不相等）**，再去覆盖**（或者说修改）**慢指针指向的元素。**就这样两者相互配合，只遍历了一遍数组，不仅**空间复杂度为O(1)，时间复杂度也仅为O(n)**

这里也附上大佬总结的**通解**：

为了让解法更具有一般性，我们将原问题的「保留 2 位」修改为「保留 k 位」。

对于此类问题，我们应该进行如下考虑：

由于是保留 k 个相同数字，对于前 k 个数字，我们可以直接保留
对于后面的任意数字，能够保留的前提是：与当前写入的位置前面的第 k 个元素进行比较，不相同则保留

## 代码

```
class Solution {
	public:
		int removeDuplicates(vector<int>& nums) {
			int n = nums.size(), j = 2;
			if (n <= 2) {
				return n;
			}
			for (int i = 2; i < n; i++) {
				if (nums[i] != nums[j - 2]) {
					nums[j] = nums[i];
					j++;
				}
			}
			return j;
		}
};
```

# [LeetCode每日一题]81. 搜索旋转排序数组 II

## 问题

```
已知存在一个按非降序排列的整数数组 nums ，数组中的值不必互不相同。

在传递给函数之前，nums 在预先未知的某个下标 k（0 <= k < nums.length）上进行了 旋转 ，使数组变为 [nums[k], nums[k+1], ..., nums[n-1], nums[0], nums[1], ..., nums[k-1]]（下标 从 0 开始 计数）。例如， [0,1,2,4,4,4,5,6,6,7] 在下标 5 处经旋转后可能变为 [4,5,6,6,7,0,1,2,4,4] 。

给你 旋转后 的数组 nums 和一个整数 target ，请你编写一个函数来判断给定的目标值是否存在于数组中。如果 nums 中存在这个目标值 target ，则返回 true ，否则返回 false 。

 

示例 1：

输入：nums = [2,5,6,0,0,1,2], target = 0
输出：true
示例 2：

输入：nums = [2,5,6,0,0,1,2], target = 3
输出：false
 

提示：

1 <= nums.length <= 5000
-10的四次方 <= nums[i] <= 10的四次方
题目数据保证 nums 在预先未知的某个下标上进行了旋转
-10的四次方 <= target <= 10的四次方
```

大水题……

## 思路及代码

```
class Solution {
public:
    bool search(vector<int>& nums, int target) {
        for (int i = 0; i < nums.size(); i++) 
            if (nums[i] == target)
                return true;
        return false;
    }
};
```

既然题解说要用二分，那就用二分法试试看吧

这题相较于常规的二分，不同点在于它是部分非单调递减有序的（后面的有序都是指非单调递减有序），这也意味着[l, mid]和[mid,r]至少有一个区间是有序的。我们**通过这个有序的区间来判断target在不在这个区间的里面**（无序区间是不好判断在不在里面的），如果在，那就在有序的区间里面找（剪掉了另外一部分，这也是二分的实质——减治），不在的话，就是另外一个区间里面找（也是剪掉了一部分）

还要注意一个特殊情况，就是重复元素带来的nums[l] == nums[mid] && nums[mid] == nums[r]，这会导致无法判断区间 [l,mid] 和区间 [mid+1,r] 哪个是有序的。例如 nums=[3,1,2,3,3,3,3]，target=2，首次二分时判断区间 [0,3] 是有序的，然后确定target在不在这里面的时候就出错了。

对于这种情况，我们只能将当前二分区间的左边界加一，右边界减一，然后在新区间上继续二分查找。

```
class Solution {
	public:
		bool search(vector<int>& nums, int target) {
			int n = nums.size();
			int l = 0, r = n - 1, mid;
			while (l <= r) {
				mid = (l + r) / 2;
				if (nums[mid] == target) {
					return true;
				}
				if (nums[l] == nums[mid] && nums[mid] == nums[r]) { //防止特殊情况
					l++;
					r--;
				} else if (nums[l] <= nums[mid]) { //左边是不是非单调递减有序的？
					if (nums[l] <= target && target < nums[mid]) { //是的话，target在不在左边？
						r = mid - 1;//在左边
					} else {
						l = mid + 1;//在右边
					}
				} else { //如果左边不是单调递减有序的话，那右边一定是
					if (nums[mid] < target && target <= nums[r]) { //在不在右边？
						l = mid + 1;//在右边
					} else {
						r = mid - 1;//不在右边
					}
				}
			}
			return false;
		}
};
```

# [LeetCode每日一题]153.寻找旋转排序数组中的最小值

## 问题

```
已知一个长度为 n 的数组，预先按照升序排列，经由 1 到 n 次 旋转 后，得到输入数组。例如，原数组 nums = [0,1,2,4,5,6,7] 在变化后可能得到：
若旋转 4 次，则可以得到 [4,5,6,7,0,1,2]
若旋转 4 次，则可以得到 [0,1,2,4,5,6,7]
注意，数组 [a[0], a[1], a[2], ..., a[n-1]] 旋转一次 的结果为数组 [a[n-1], a[0], a[1], a[2], ..., a[n-2]] 。

给你一个元素值 互不相同 的数组 nums ，它原来是一个升序排列的数组，并按上述情形进行了多次旋转。请你找出并返回数组中的 最小元素 。

 

示例 1：

输入：nums = [3,4,5,1,2]
输出：1
解释：原数组为 [1,2,3,4,5] ，旋转 3 次得到输入数组。
示例 2：

输入：nums = [4,5,6,7,0,1,2]
输出：0
解释：原数组为 [0,1,2,4,5,6,7] ，旋转 4 次得到输入数组。
示例 3：

输入：nums = [11,13,15,17]
输出：11
解释：原数组为 [11,13,15,17] ，旋转 4 次得到输入数组。
 

提示：

n == nums.length
1 <= n <= 5000
-5000 <= nums[i] <= 5000
nums 中的所有整数 互不相同
nums 原来是一个升序排序的数组，并进行了 1 至 n 次旋转
```

## 思路及代码

又是水题

先上三种无脑实现方法，sort()是其中最快的一种……

```
class Solution {
	public:
		int findMin(vector<int>& nums) {
			sort(nums.begin(), nums.end());
			return nums[0];
		}
};
```

```
class Solution {
	public:
		int findMin(vector<int>& nums) {
			int n = nums.size(), min = nums[0];
			for(int i = 0; i < n; i++){
				if(nums[i] < min){
					min = nums[i];
				}
			}
			return min;
		}
};
```

```
class Solution {
	public:
		int findMin(vector<int>& nums) {
			return *min_element(nums.begin(), nums.end());
		}
};
```

大佬解法：

![image.png](https://i.loli.net/2021/10/26/tepyW5A6RrFHPvw.png)

经过旋转的数组，显然前半段满足 >= nums[0]，而后半段不满足 >= nums[0]。我们可以以此作为依据，通过「二分」找到旋转点。然后通过旋转点找到全局最小值即可。

```
class Solution {
	public:
		int findMin(vector<int> nums) {
			int n = nums.size();
			int l = 0, r = n - 1;
			while (l < r) {
				int mid = (l + r + 1) >> 1;
				if (nums[mid] >= nums[0]) {
					l = mid;
				} else {
					r = mid - 1;
				}
			}
			return r + 1 < n ? nums[r + 1] : nums[0];
		}
};
```

二分模板

```
「二分」模板其实有两套，主要是根据 check(mid) 函数为 true 时，需要调整的是 l 指针还是 r 指针来判断。

当 check(mid) == true 调整的是 l 时：计算 mid 的方式应该为 mid = l + r + 1 >> 1：

long l = 0, r = 1000009;
while (l < r) {
    long mid = l + r + 1 >> 1;
    if (check(mid)) {
        l = mid;
    } else {
        r = mid - 1;
    }
}
当 check(mid) == true 调整的是 r 时：计算 mid 的方式应该为 mid = l + r >> 1：

long l = 0, r = 1000009;
while (l < r) {
    long mid = l + r >> 1;
    if (check(mid)) {
        r = mid;
    } else {
        l = mid + 1;
    }
}
```

# [LeetCode]丑数 II&C++中priority_queue和unordered_set的使用

考虑到现实因素，LeetCode每日一题不再每天都写题解了（甚至有可能鸽掉题目？……）但对于非常有意思和新奇的做法，还是会尽量记录下来

## 问题

```
给你一个整数 n ，请你找出并返回第 n 个 丑数 。
丑数 就是只包含质因数 2、3 和/或 5 的正整数。

示例 1：
输入：n = 10
输出：12
解释：[1, 2, 3, 4, 5, 6, 8, 9, 10, 12] 是由前 10 个丑数组成的序列。

示例 2：
输入：n = 1
输出：1
解释：1 通常被视为丑数。

提示：
1 <= n <= 1690
```

## 思路及代码

### 解法一：打表

看到后第一眼是想要打表……

代码略

### 解法二：最小堆

要得到从小到大的第 n 个丑数，可以使用**最小堆**实现。

初始时堆为空。首先将最小的丑数 1 加入堆。

每次取出堆顶元素 x，则 x 是堆中最小的丑数，由于 2x, 3x, 5x也是丑数，因此将 2x, 3x, 5x 加入堆。

上述做法会导致堆中出现重复元素的情况。为了避免重复元素，可以使用哈希集合去重，避免相同元素多次加入堆。

在排除重复元素的情况下，第 n 次从最小堆中取出的元素即为第 n 个丑数。

```
class Solution {
public:
    int nthUglyNumber(int n) {
        vector<int> factors = {2, 3, 5};
        unordered_set<long> seen;
        priority_queue<long, vector<long>, greater<long>> heap;
        seen.insert(1L);
        heap.push(1L);
        int ugly = 0;
        for (int i = 0; i < n; i++) {
            long curr = heap.top();
            heap.pop();
            ugly = (int)curr;
            for (int factor : factors) {
                long next = curr * factor;
                if (!seen.count(next)) {//count()返回给定主键出现的次数，也即next出现的次数，若为0则加入到容器中
                    seen.insert(next);
                    heap.push(next);
                }
            }
        }
        return ugly;
    }
};
```

### 解法三：三指针

```
class Solution {
    public int nthUglyNumber(int n) {
        // ans 用作存储已有丑数（从下标 1 开始存储，第一个丑数为 1）
        int[] ans = new int[n + 1];
        ans[1] = 1;
        // 由于三个有序序列都是由「已有丑数」*「质因数」而来
        // i2、i3 和 i5 分别代表三个有序序列当前使用到哪一位「已有丑数」下标（起始都指向 1）
        for (int i2 = 1, i3 = 1, i5 = 1, idx = 2; idx <= n; idx++) {
            // 由 ans[iX] * X 可得当前有序序列指向哪一位
            int a = ans[i2] * 2, b = ans[i3] * 3, c = ans[i5] * 5;
            // 将三个有序序列中的最小一位存入「已有丑数」序列，并将其下标后移
            int min = min(a, min(b, c));
            // 由于可能不同有序序列之间产生相同丑数，因此只要一样的丑数就跳过（不能使用 else if ）
            if (min == a) i2++; 
            if (min == b) i3++;
            if (min == c) i5++;
            ans[idx] = min;
        }
        return ans[n];
    }
}
```

## C++中priority_queue的使用

下面大部分内容摘自互联网

### priority_queue

对于这个模板类priority_queue，它是STL所提供的一个非常有效的容器。

作为队列的一个延伸，优先队列包含在头文件 <queue> 中。

### 简述

优先队列是一种比较重要的数据结构，它是由二项队列编写而成的，可以以O(log n) 的效率查找一个队列中的最大值或者最小值，其中是最大值还是最小值是根据创建的优先队列的性质来决定的。

### 模板参数

优先队列有三个参数，其声明形式为：

```
priority_queue< type, container, function >
```

这三个参数，后面两个可以省略，第一个不可以。
其中：

**type**：数据类型；
**container**：实现优先队列的底层容器；
**function**：元素之间的比较方式；
对于**container，要求必须是数组形式实现的容器，例如vector、deque，而不能使list。**
在STL中，默认情况下（不加后面两个参数）是以**vector**为容器，以 **operator<** 为比较方式，所以在**只使用第一个参数时，优先队列默认是一个最大堆**，**每次输出的堆顶元素是此时堆中的最大元素。**

### 成员函数

假设type类型为**int**，则：

```
bool empty() const
//返回值为true，说明队列为空；
int size() const
//返回优先队列中元素的数量；
void pop()
//删除队列顶部（最大或最小）的元素，也即根节点
int top()
//返回队列中的顶部（最大或最小的）元素，但不删除该元素；
void push(int arg)
//将元素arg插入到队列之中；
```

### 大顶堆与小顶堆

**大顶堆**

```
//构造一个空的优先队列（此优先队列默认为大顶堆）
priority_queue<int> big_heap;   

//另一种构建大顶堆的方法
priority_queue<int,vector<int>,less<int> > big_heap2;
```

**小顶堆**

```
//构造一个空的优先队列,此优先队列是一个小顶堆
priority_queue<int,vector<int>,greater<int> > small_heap;  
```

需要注意的是，如果使用less<int>和greater<int>，需要头文件：

```
#include <functional>
```

### 基本类型优先队列的例子：

```
#include<iostream>
#include <queue>
using namespace std;
int main()
{
    //对于基础类型 默认是大顶堆
    priority_queue<int> a;
    //等同于 priority_queue<int, vector<int>, less<int> > a;

    //      这里一定要有空格，不然成了右移运算符↓↓
    priority_queue<int, vector<int>, greater<int> > c;  //这样就是小顶堆
    priority_queue<string> b;

    for (int i = 0; i < 5; i++)
    {
        a.push(i);
        c.push(i);
    }
    while (!a.empty())
    {
        cout << a.top() << ' ';
        a.pop();
    }
    cout << endl;

    while (!c.empty())
    {
        cout << c.top() << ' ';
        c.pop();
    }
    cout << endl;

    b.push("abc");
    b.push("abcd");
    b.push("cbd");
    while (!b.empty())
    {
        cout << b.top() << ' ';
        b.pop();
    }
    cout << endl;
    return 0;
}
```

结果：

```
4 3 2 1 0
0 1 2 3 4
cbd abcd abc
```

## unordered_set容器

unordered_set 容器，可直译为“无序 set 容器”，即 unordered_set 容器和 set 容器很像，唯一的区别就在于 set 容器会自行对存储的数据进行排序，而 unordered_set 容器不会。

总的来说，unordered_set 容器具有以下几个特性：
**1.不再以键值对的形式存储数据，而是直接存储数据的值；**
**2.容器内部存储的各个元素的值都互不相等，且不能被修改。**
**3.不会对内部存储的数据进行排序**

```
对于 unordered_set 容器不以键值对的形式存储数据，读者也可以这样认为，即 unordered_set 存储的都是键和值相等的键值对，为了节省存储空间，该类容器在实际存储时选择只存储每个键值对的值。
```

另外，实现 unordered_set 容器的模板类定义在<unordered_set>头文件，并位于 std 命名空间中。这意味着，如果程序中需要使用该类型容器，则首先应该包含如下代码：

注意，第二行代码不是必需的，但如果不用，则程序中只要用到该容器时，必须手动注明 std 命名空间

```
#include <unordered_set>
using namespace std;
```

### 创建C++ unordered_set容器

前面介绍了如何创建 unordered_map 和 unordered_multimap 容器，值得一提的是，创建它们的所有方式完全适用于 unordereded_set 容器。不过，考虑到一些读者可能尚未学习其它无序容器，因此这里还是讲解一下创建 unordered_set 容器的几种方法。

1) 通过调用 unordered_set 模板类的默认构造函数，可以创建空的 unordered_set 容器。比如：

```
std::unordered_set<std::string> uset;
```

如果程序已经引入了 std 命名空间，这里可以省略所有的 std::。

由此，就创建好了一个可存储 string 类型值的 unordered_set 容器，该容器底层采用默认的哈希函数 hash<Key> 和比较函数 equal_to<Key>。

2) 当然，在创建 unordered_set 容器的同时，可以完成初始化操作。比如：

```
std::unordered_set<std::string> uset{ "http://c.biancheng.net/c/",
                                      "http://c.biancheng.net/java/",
                                      "http://c.biancheng.net/linux/" };
```

通过此方法创建的 uset 容器中，就包含有 3 个 string 类型元素。

通过此方法创建的 uset 容器中，就包含有 3 个 string 类型元素。

3) 还可以调用 unordered_set 模板中提供的复制（拷贝）构造函数，将现有 unordered_set 容器中存储的元素全部用于为新建 unordered_set 容器初始化。

例如，在第二种方式创建好 uset 容器的基础上，再创建并初始化一个 uset2 容器：

```
std::unordered_set<std::string> uset2(uset);
```

由此，umap2 容器中就包含有 umap 容器中所有的元素。

除此之外，C++ 11 标准中还向 unordered_set 模板类增加了移动构造函数，即以右值引用的方式，利用临时 unordered_set 容器中存储的所有元素，给新建容器初始化。例如：

```
//返回临时 unordered_set 容器的函数
std::unordered_set <std::string> retuset() {
    std::unordered_set<std::string> tempuset{ "http://c.biancheng.net/c/",
                                              "http://c.biancheng.net/java/",
                                              "http://c.biancheng.net/linux/" };
    return tempuset;
}
```

```
//调用移动构造函数，创建 uset 容器
std::unordered_set<std::string> uset(retuset());
```


注意，无论是调用复制构造函数还是拷贝构造函数，必须保证 2 个容器的类型完全相同。

4) 当然，如果不想全部拷贝，可以使用 unordered_set 类模板提供的迭代器，在现有 unordered_set 容器中选择部分区域内的元素，为新建 unordered_set 容器初始化。例如：

```
//传入 2 个迭代器，
std::unordered_set<std::string> uset2(++uset.begin(),uset.end());
```

通过此方式创建的 uset2 容器，其内部就包含 uset 容器中除第 1 个元素外的所有其它元素。

### C++ unordered_set容器的成员方法

unordered_set 类模板中，提供了如表  所示的成员方法。

| 成员方法           | 功能                                                         |
| ------------------ | ------------------------------------------------------------ |
| begin()            | 返回指向容器中第一个元素的正向迭代器。                       |
| end();             | 返回指向容器中最后一个元素之后位置的正向迭代器。             |
| cbegin()           | 和 begin() 功能相同，只不过其返回的是 const 类型的正向迭代器。 |
| cend()             | 和 end() 功能相同，只不过其返回的是 const 类型的正向迭代器。 |
| empty()            | 若容器为空，则返回 true；否则 false。                        |
| size()             | 返回当前容器中存有元素的个数。                               |
| max_size()         | 返回容器所能容纳元素的最大个数，不同的操作系统，其返回值亦不相同。 |
| find(key)          | 查找以值为 key 的元素，如果找到，则返回一个指向该元素的正向迭代器；反之，则返回一个指向容器中最后一个元素之后位置的迭代器（如果 end() 方法返回的迭代器）。 |
| **count(key)**     | **在容器中查找值为 key 的元素的个数。**                      |
| equal_range(key)   | 返回一个 pair 对象，其包含 2 个迭代器，用于表明当前容器中值为 key 的元素所在的范围。 |
| emplace()          | 向容器中添加新元素，效率比 insert() 方法高。                 |
| emplace_hint()     | 向容器中添加新元素，效率比 insert() 方法高。                 |
| insert()           | 向容器中添加新元素。                                         |
| erase()            | 删除指定元素。                                               |
| clear()            | 清空容器，即删除容器中存储的所有元素。                       |
| swap()             | 交换 2 个 unordered_map 容器存储的元素，前提是必须保证这 2 个容器的类型完全相等。 |
| bucket_count()     | 返回当前容器底层存储元素时，使用桶（一个线性链表代表一个桶）的数量。 |
| max_bucket_count() | 返回当前系统中，unordered_map 容器底层最多可以使用多少桶。   |
| bucket_size(n)     | 返回第 n 个桶中存储元素的数量。                              |
| bucket(key)        | 返回值为 key 的元素所在桶的编号。                            |
| load_factor()      | 返回 unordered_map 容器中当前的负载因子。负载因子，指的是的当前容器中存储元素的数量（size()）和使用桶数（bucket_count()）的比值，即 load_factor() = size() / bucket_count()。 |
| max_load_factor()  | 返回或者设置当前 unordered_map 容器的负载因子。              |
| rehash(n)          | 将当前容器底层使用桶的数量设置为 n。                         |
| reserve()          | 将存储桶的数量（也就是 bucket_count() 方法的返回值）设置为至少容纳count个元（不超过最大负载因子）所需的数量，并重新整理容器。 |
| hash_function()    | 返回当前容器使用的哈希函数对象。                             |

注意，此容器模板类中没有重载 [ ] 运算符，也没有提供 at() 成员方法。不仅如此，由于 **unordered_set 容器内部存储的元素值不能被修改**，因此无论使用哪个迭代器方法获得的迭代器，都不能用于修改容器中元素的值。

另外，对于实现互换 2 个相同类型 unordered_set 容器的所有元素，除了调用表 2 中的 swap() 成员方法外，还可以使用 STL 标准库提供的 swap() 非成员函数，它们具有相同的名称，用法也相同（都只需要传入 2 个参数即可），仅是调用方式上有差别。

下面的样例演示了表 2 中部分成员方法的用法：

```
#include <iostream>
#include <string>
#include <unordered_set>
using namespace std;
int main()
{
    //创建一个空的unordered_set容器
    std::unordered_set<std::string> uset;
    //给 uset 容器添加数据
    uset.emplace("http://c.biancheng.net/java/");
    uset.emplace("http://c.biancheng.net/c/");
    uset.emplace("http://c.biancheng.net/python/");
    //查看当前 uset 容器存储元素的个数
    cout << "uset size = " << uset.size() << endl;
    //遍历输出 uset 容器存储的所有元素
    for (auto iter = uset.begin(); iter != uset.end(); ++iter) {
        cout << *iter << endl;
    }
    return 0;
}
```

程序执行结果为：

```
uset size = 3
http://c.biancheng.net/java/
http://c.biancheng.net/c/
http://c.biancheng.net/python/
```

# [LeetCode]179. 最大数

## 问题

```
给定一组非负整数 nums，重新排列每个数的顺序（每个数不可拆分）使之组成一个最大的整数。

注意：输出结果可能非常大，所以你需要返回一个字符串而不是整数。

示例 1：
输入：nums = [10,2]
输出："210"
示例 2：
输入：nums = [3,30,34,5,9]
输出："9534330"
示例 3：
输入：nums = [1]
输出："1"
示例 4：
输入：nums = [10]
输出："10"

提示：
1 <= nums.length <= 100
0 <= nums[i] <= 10的九次方
```

## 思路及代码

对于 nums 中的任意两个值 a 和 b，我们无法直接从常规角度上确定其大小/先后关系。

但我们可以根据「结果」来决定 a 和 b 的排序关系：

**如果拼接结果 ab 要比 ba 好，那么我们会认为 a 应该放在 b 前面。**

这是一种贪心的思想，可以证明，**该贪心策略能取到全局最优解。**

假设存在一个最优序列不满足该排序规则，那么必然存在至少一对相邻数字 a 与 b，我们将 a 与 b 交换后新序列的值必然增加，与假设矛盾。因此，满足该排序规则是该序列最优的充分条件。

这里证明从略，因为做没做过这题的人几乎都无法在面试中给出严格证明。

代码如下：

```
#include<bits/stdc++.h>
using namespace std;
class Solution {
	public:
		static bool cmp(string a, string b) {//不加static会报错
			return a + b > b + a;
		}
		string largestNumber(vector<int>& nums) {
			vector<string> str;
			for (int i : nums) {
				str.push_back(to_string(i));//将容器vectors中的元素都变为字符串加入到str容器中
			}
			sort(str.begin(), str.end(), cmp);
			string ans;
			if (str[0] == "0") {
				ans = "0";
			} else {
				for (string i : str) {
					ans += i;
				}
			}
			return ans;
		}
};

int main() {
	Solution s;
	vector<int> nums = {3, 30, 34, 5, 9};
	cout << s.largestNumber(nums) << endl;
}
```

结论：**看到要求两个整数 x,y 如何拼接得到结果更大时，就想到先转字符串，然后比较 x+y 和 y+x。这是经验。**

**n个整数也是如此，因为可以证明当其局部满足该条件（拼接结果最大）时，整体也满足该条件。**
