// A C++ DLL with MSVC's names, for the demangler and the PE reader: a namespace, a class with
// a constructor, a destructor, virtual methods and operators, a template, a static member and an
// overloaded function, exported; and imports from the C++ runtime by their MSVC names
// (vcruntime.def, msvcp.def). Built by build.sh with clang and lld-link, without the CRT.
namespace std {
[[noreturn]] void _Xlength_error(const char *);
}

extern "C" int _fltused = 0;

namespace geo {

template <typename T> struct Box {
  T value;
  T get() const { return value; }
};

class __declspec(dllexport) Point {
 public:
  Point(int x, int y) : x_(x), y_(y) {}
  virtual ~Point() {}
  virtual int length() const { return x_ * x_ + y_ * y_; }
  Point operator+(const Point &o) const { return Point(x_ + o.x_, y_ + o.y_); }
  bool operator==(const Point &o) const { return x_ == o.x_ && y_ == o.y_; }
  static int count;

 private:
  int x_, y_;
};

int Point::count = 0;

__declspec(dllexport) int scale(int v, int by) { return v * by; }
__declspec(dllexport) double scale(double v, double by) { return v * by; }
__declspec(dllexport) int sum(const Box<int> &a, const Box<int> &b) { return a.get() + b.get(); }
__declspec(dllexport) int checked(int n) {
  if (n < 0) std::_Xlength_error("negative");
  return n;
}

template struct __declspec(dllexport) Box<double>;

}  // namespace geo

extern "C" __declspec(dllexport) int plain(int x) { return geo::scale(x, 2) + geo::Point(1, 2).length(); }
