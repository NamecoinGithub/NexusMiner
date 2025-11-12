# Contributing to NexusMiner

Thank you for your interest in contributing to NexusMiner! This document provides guidelines and instructions for contributing.

## 🤝 How to Contribute

### Reporting Bugs

If you find a bug, please create an issue on GitHub with:
- Clear description of the problem
- Steps to reproduce
- Expected vs actual behavior
- Your environment (OS, GPU type, build configuration)
- Relevant log output

### Suggesting Features

Feature requests are welcome! Please:
- Check if the feature has already been requested
- Clearly describe the feature and its benefits
- Provide use cases

### Code Contributions

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes**
   - Follow the existing code style
   - Add comments where necessary
   - Keep changes focused and atomic

4. **Test your changes**
   ```bash
   mkdir build && cd build
   cmake -DCMAKE_BUILD_TYPE=Release ..
   make -j$(nproc)
   ./NexusMiner --check
   ```

5. **Commit your changes**
   ```bash
   git add .
   git commit -m "Brief description of changes"
   ```

6. **Push and create a Pull Request**
   ```bash
   git push origin feature/your-feature-name
   ```

## 📝 Coding Standards

- Use meaningful variable and function names
- Keep functions focused on a single responsibility
- Comment complex algorithms
- Match the existing code style (4-space indentation, etc.)

## 🏗️ Build System

NexusMiner uses CMake. When adding new features:
- Update CMakeLists.txt if adding new files
- Ensure all build presets still work
- Test on multiple platforms if possible

## ✅ Testing

Before submitting:
- [ ] Code compiles without warnings
- [ ] Application runs and passes config check
- [ ] No memory leaks (run with valgrind if possible)
- [ ] Existing functionality still works

## 📄 License

By contributing, you agree that your contributions will be licensed under the GNU GPL v3.0 License.

## 💬 Questions?

Join us on [Telegram](https://t.me/NexusMiners) or open a discussion on GitHub!
